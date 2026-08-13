//! The transaction coordinator: drives **concurrent** Cypher transactions over one shared record
//! store with Serializable Snapshot Isolation (`04-technical-design.md` §5.4/§5.7; `rmp` task #46).
//!
//! [`crate::record_graph::RecordStoreGraph`] already runs one transaction at a time over the
//! MVCC-native store (`rmp` task #45). [`TxnCoordinator`] is the layer above that lets several
//! transactions be open at once and makes their concurrent execution **serializable**:
//!
//! - it owns the one shared [`RecordStore`] (so several transactions read/write the same graph) and
//!   uses the store itself as the timestamp source (the store became the commit-timestamp oracle in
//!   `rmp` task #45: [`RecordStore::snapshot_ts`] is the begin snapshot, and a `commit` advances it);
//! - it owns the shared [`SsiTracker`] from `graphus-txn` — the **complete,
//!   tested** SSI machine — so each transaction's statements contribute non-blocking SIREAD markers
//!   and rw-antidependency edges. Write-write conflicts are not handled here: since `rmp` #971 they
//!   are detected first-updater-wins in the storage layer, on the entity's own MVCC header, by
//!   `RecordStore::ensure_no_conflicting_writer`, which refuses the second writer retriably without
//!   ever waiting;
//! - at [`commit`](TxnCoordinator::commit) it runs SSI validation (SERIALIZABLE only) and aborts a
//!   **pivot** on a dangerous structure with a retriable serialization error (PostgreSQL safe-retry:
//!   at least one transaction in any unsafe set commits, no livelock). [`IsolationLevel::Snapshot`]
//!   is the documented weaker opt-in that skips validation and therefore permits write-skew.
//!
//! ## Driving a transaction
//!
//! ```ignore
//! let mut coord = TxnCoordinator::new(store);
//! let t1 = coord.begin_serializable();
//! {
//!     // One statement: borrow a per-statement graph seam, run the executor over it, drop it.
//!     let mut g = coord.statement(t1)?;
//!     let mut cursor = execute(&plan, &bound, &mut g)?;
//!     let _rows = cursor.collect_all()?;
//!     // (check `g.has_error()` before relying on the rows)
//! }
//! coord.commit(t1)?; // may return a retriable serialization failure under SSI
//! ```
//!
//! A transaction spans many statements: [`begin`](TxnCoordinator::begin) once, any number of
//! [`statement`](TxnCoordinator::statement) executions (the store is borrowed only for each
//! statement's duration, never for the whole transaction), then [`commit`](TxnCoordinator::commit)
//! or [`rollback`](TxnCoordinator::rollback). Markers accumulate across statements in the
//! coordinator's shared trackers.
//!
//! ## Read polarity: this file holds two opposite ones (`rmp` task #905)
//!
//! The index refills (`index_one_node*`, `index_one_rel*`) and the constraint-validation walks
//! (`validate_existing_*_against_constraint`) sit a few thousand lines apart in this file and make
//! **opposite** demands of the same store reads. They are not variations on a theme; they discharge
//! different obligations, and the whole of `rmp` tasks #902 and #904 was one being written with the
//! other's read:
//!
//! * a **refill** has no snapshot. It populates a candidate structure that every consumer re-checks,
//!   and a re-check can remove a candidate but never resurrect one, so the tree must be a
//!   **superset** — every property version (`rmp` #766), and the live-OR-retained label union
//!   ([`RecordStore::node_label_superset`], `rmp` #904), never the live word;
//! * a **constraint verdict** is written into the catalogue and nothing re-checks it, so it must be
//!   a **decision** — exactly what the DDL transaction's snapshot sees, resolved through
//!   [`RecordStore::decision_scan_node_properties`] / `decision_scan_rel_properties`, which cannot
//!   be called without that snapshot;
//! * `rebuild_zone_column` is a third thing again: a zone map **prunes** an id range before any
//!   re-check runs and nothing repairs one, so it must be **conservative** and takes the refill's
//!   superset gate.
//!
//! [`graphus_storage::scan_polarity`] states the rule in full. The census that keeps this file
//! honest — including every raw read here that is deliberately correct, and why — is
//! `tests/read_polarity_census.rs`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::shared_cell::{SharedCell, SharedRef};

use graphus_core::Value;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, Timestamp, TxnId};

/// One version of one property, as the index build sees it: the MVCC stamps plus the decoded value
/// (`rmp` task #766). `RecordStore::superset_scan_node_property_values` /
/// `superset_scan_rel_property_values` discard the stamps, so the composite builds read
/// `superset_scan_node_properties` / `superset_scan_rel_properties` and keep them.
struct PropVersion {
    /// The creating transaction's stamp (`MvccHeader::created_ts`), raw.
    xmin: u64,
    /// The expiring transaction's stamp (`MvccHeader::expired_ts`), raw; `0` = live.
    xmax: u64,
    value: Value,
}

/// The instant-index half-open range `[lo, hi)` over the sorted `instants` on which version `v` is
/// visible from the view owned by `owner` (`TxnId(0)` for the committed view), or [`None`] if it is
/// visible at no instant.
///
/// This is [`graphus_txn::is_visible_via`] turned inside-out: rather than testing one snapshot, it returns
/// the whole *contiguous* span of snapshots that see `v`. Visibility is monotone in the snapshot time —
/// the creator becomes visible at one stamp (clause 1) and the expirer hides it at a later one
/// (clause 2), `04 §5.3` — so the visible snapshots are exactly one interval, and each stamp that bounds
/// it is itself an instant (it was collected from some version's `xmin` / `xmax`).
///
/// Stamps resolve through the `registry`, NEVER from the raw word: a commit settles LAZILY, so a
/// long-committed version still reads `InFlight(w)` and only the registry knows its real commit instant.
/// Deciding visibility from the raw stamp alone would split a node's versions into disjoint per-writer
/// views and drop the tuple that mixes one writer's committed value with another's — the missing
/// candidate this whole construction exists to prevent. That premise fell during `rmp` #766.
///
/// The one exception the resolver cannot express is the owner's OWN uncommitted write: it has no commit
/// timestamp yet is visible to `owner` from `t = 0` (an own uncommitted deletion, symmetrically, hides
/// the version from `owner` at every instant). Those two cases are handled explicitly before the
/// resolver; everything else — committed, foreign in-flight, aborted, or the `0`/live sentinel — is what
/// [`CommitRegistry::resolve_commit_ts`] already classifies.
///
/// # Errors
/// Propagates a stamp-resolution fault from the [`CommitOracle`] door (`rmp` #1069). A candidate
/// whose validity interval cannot be computed must fail the DDL, never silently contribute no
/// tuple — that is a dropped candidate, i.e. an admitted committed duplicate on a KEY constraint.
fn visible_instant_range(
    v: &PropVersion,
    owner: TxnId,
    registry: &CommitRegistry,
    instants: &[Timestamp],
    instant_index: &HashMap<Timestamp, usize>,
) -> Result<Option<(usize, usize)>> {
    let n = instants.len();
    // First instant index at or after `ts`. Every resolved commit stamp is an instant, so the map hits;
    // the `partition_point` fallback keeps a (never-taken) miss sound rather than panicking inside a DDL.
    let idx_of = |ts: Timestamp| -> usize {
        instant_index
            .get(&ts)
            .copied()
            .unwrap_or_else(|| instants.partition_point(|&x| x < ts))
    };
    // `lo` = first instant whose snapshot sees the creator (clause 1). An own uncommitted creator is
    // seen from `t = 0`; otherwise the resolver decides — `None` means visible at no instant.
    let lo = if registry.names_own_write(v.xmin, owner)? {
        0
    } else {
        match registry.resolve_commit_ts(v.xmin)? {
            Some(ts) => idx_of(ts),
            None => return Ok(None),
        }
    };
    // `hi` = first instant whose snapshot has the expirer hide it (clause 2); `n` when nothing hides it.
    // An own uncommitted deletion hides from `t = 0` (an empty span); otherwise the resolver decides —
    // `None` (the `0`/live sentinel, a foreign in-flight, or an aborted expirer) never hides it.
    let hi = if registry.names_own_write(v.xmax, owner)? {
        0
    } else {
        match registry.resolve_commit_ts(v.xmax)? {
            Some(ts) => idx_of(ts),
            None => n,
        }
    };
    Ok((lo < hi).then_some((lo, hi)))
}

/// Path-halving "next still-empty slot" lookup for the newest-priority interval fill in
/// [`composite_candidate_tuples`]. `next[i] == i` marks slot `i` empty; filling `i` sets `next[i] = i+1`
/// so later lookups skip it. Returns the smallest `j >= i` still empty. `next` has length `n + 1`, so
/// the sentinel `next[n] == n` bounds the walk and the returned index never exceeds `n`.
fn uf_next_empty(next: &mut [usize], mut i: usize) -> usize {
    while next[i] != i {
        next[i] = next[next[i]]; // path halving keeps the amortised cost ~O(1)
        i = next[i];
    }
    i
}

/// A hash of `tuple` consistent with `Vec<Value>`'s structural [`PartialEq`], for the dedup fast-path in
/// [`composite_candidate_tuples`]. Structurally-equal tuples always hash equal, so they always land in
/// the same bucket where the exact `==` confirm decides membership; the coarse fallback for non-scalar
/// variants (bucket by discriminant only) is therefore always SOUND — it can only cost extra confirms,
/// never a wrong dedup. Scalars — the near-universal composite key shapes — are hashed precisely, with
/// floats canonicalised so `+0.0`/`-0.0` agree (they are `==`) and every `NaN` shares one bucket (it is
/// never `==`, so the confirm keeps both, exactly as the old `Vec::contains` did).
fn composite_tuple_hash(tuple: &[Value]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tuple.len().hash(&mut h);
    for v in tuple {
        std::mem::discriminant(v).hash(&mut h);
        match v {
            Value::Boolean(b) => b.hash(&mut h),
            Value::Integer(i) => i.hash(&mut h),
            Value::Float(f) => {
                let bits = if *f == 0.0 {
                    0
                } else if f.is_nan() {
                    u64::MAX
                } else {
                    f.to_bits()
                };
                bits.hash(&mut h);
            }
            Value::String(s) => s.hash(&mut h),
            Value::Bytes(b) => b.hash(&mut h),
            // Non-scalar variants (Null, List, Map, temporal, Point) bucket by discriminant only: sound
            // (equal values share a discriminant) and immaterial in practice (rare as composite keys).
            _ => {}
        }
    }
    h.finish()
}

/// Every composite tuple any reader can observe for one entity, given `per_key[i]` = the chain of
/// versions of the i-th covered property, newest first (`rmp` task #766).
///
/// # Why this shape, and why it is a complete superset
///
/// A reader never mixes versions freely: at snapshot `T` it resolves the newest version of EACH key
/// visible at that ONE `T`. So the only observable tuples are the *per-instant* tuples, and the tuple
/// can only change where some version becomes visible or expires — i.e. at a stamp in the chain. The
/// instants below are therefore the distinct committed stamps (plus `0`, the before-anything instant).
///
/// An in-flight writer is the exception, and the reason this is not simply "one tuple per timestamp":
/// it sees its OWN uncommitted writes, which carry no commit timestamp. Its tuple is (its own newest
/// version where it wrote, else newest committed at ITS snapshot `S`) — a tuple no committed instant
/// emits. Each in-flight writer therefore gets its own view. Its `S` is unknown here, so the view is
/// evaluated at EVERY committed instant: for `T` = the largest instant `<= S`, "newest committed `<= T`"
/// is exactly "newest committed `<= S`", so the writer's real tuple is always among those emitted. That
/// over-approximation is sound precisely because a superset is safe — extra tuples are false positives
/// the seek's re-check drops, whereas a MISSING tuple is unfixable: a re-check can remove a candidate
/// but never resurrect one, and for the NODE KEY / REL KEY trees a missing candidate means the write
/// path's duplicate check finds nothing and ADMITS A COMMITTED DUPLICATE (`rmp` #683 / #765).
///
/// # Complexity — two different bounds, do not conflate them (`rmp` task #774)
///
/// With `V` = the number of distinct instants, `k` = the covered-property count, `W` = the in-flight
/// writers:
///
/// - **Emitted tuples** (what bounds INDEX SIZE): `O((1 + W) * V)`. Linear — one tuple per (view,
///   instant) before dedup.
/// - **Construction cost** (what bounds DDL TIME): `O((1 + W) * k * V)` (amortised), plus `O(V log V)`
///   to sort the instants once and `O((1 + W) * V)` expected for the hashed dedup. Linear in `V`.
///
/// The construction is a MERGE-STYLE SWEEP: for each view and each key, every version is visible over a
/// contiguous instant range (see [`visible_instant_range`]), so the per-key chain is swept newest-first,
/// painting only the still-empty instants of each range through a union-find "next empty" cursor
/// ([`uf_next_empty`]) — each instant is written exactly once, giving `O(V)` per (view, key) instead of
/// the `find`-per-instant scan that made this `O(k * V^2)` before `rmp` #774. The dedup is a hashed set
/// ([`composite_tuple_hash`] + an exact `==` confirm), replacing the old `O(emitted^2)` `Vec::contains`.
///
/// Both matter because chains are NOT pruned in practice — `RecordStore::gc` has no production trigger
/// (`rmp` #305 owns scheduling) — so `V` on a hot node is bounded by nothing and every index/constraint
/// DDL pays this per node.
///
/// Measured on one node under a 3-key NODE KEY (debug build), the CONSTRUCTION alone (isolated from the
/// rebuild's store reads / tree inserts, so the term this bound describes is what is timed), the pre-#774
/// `find`-per-instant construction vs this sweep, on the dev host in one run:
///
/// | V    | pre-#774 `O(k*V^2)` | this sweep |
/// |------|---------------------|------------|
/// | 8    | 0.009 ms            | 0.036 ms   |
/// | 16   | 0.023 ms            | 0.068 ms   |
/// | 64   | 0.197 ms            | 0.250 ms   |
/// | 256  | 2.83 ms             | 0.96 ms    |
/// | 1024 | 44.08 ms            | 4.02 ms  (11x) |
///
/// Exponent per 4x step: pre-#774 `1.35 → 1.55 → 1.92 → 1.98` (heading to 2); this sweep
/// `0.92 → 0.94 → 0.97 → 1.04` (flat at 1). The sweep's larger fixed cost makes it slower below `V ≈ 100`
/// (its `BTreeSet` / `HashMap` / union-find scratch), and decisively faster as `V` grows — the right
/// trade for an UNBOUNDED chain. At the full-rebuild level the same 3-key scenario went `227 ms → 63 ms`
/// at `V = 1024` (the recorded `rmp` #766 residual measured `249 ms`), the remainder being the rebuild's
/// own linear store/insert floor. `construction_scales_sub_quadratically` guards the shape.
///
/// # Errors
/// Propagates a stamp-resolution fault from the [`CommitOracle`] door (`rmp` #1069) — see
/// [`visible_instant_range`] for why a fault must fail the DDL rather than drop a candidate.
fn composite_candidate_tuples(
    per_key: &[Vec<&PropVersion>],
    registry: &CommitRegistry,
) -> Result<Vec<Vec<Value>>> {
    // The instant grid + the in-flight writer views. `instants` = distinct committed stamps (resolved
    // through the registry, never the raw word — see `visible_instant_range`) UNION `{0}`; a `BTreeSet`
    // yields them SORTED and deduped in `O(V log V)` — the old `Vec::contains` de-dup here was itself
    // `O(V^2)`. `writers` = the distinct in-flight writers (few in practice; a linear `contains` is fine).
    let mut instant_set: BTreeSet<Timestamp> = BTreeSet::new();
    instant_set.insert(Timestamp(0));
    let mut writers: Vec<TxnId> = Vec::new();
    for versions in per_key {
        for v in versions {
            for raw in [v.xmin, v.xmax] {
                match registry.resolve_commit_ts(raw)? {
                    Some(ts) => {
                        instant_set.insert(ts);
                    }
                    None => {
                        // The writer the word NAMES, through the door — never `resolve_stamp`, whose
                        // `InFlight` arm is dead through the registry (`rmp` #522 / #778).
                        if let Some(w) = registry.names_writer(raw)?
                            && !writers.contains(&w)
                        {
                            writers.push(w);
                        }
                    }
                }
            }
        }
    }
    let instants: Vec<Timestamp> = instant_set.into_iter().collect();
    let n = instants.len();
    // `O(1)` stamp -> instant-index lookup for the interval bounds (see `visible_instant_range`).
    let instant_index: HashMap<Timestamp, usize> =
        instants.iter().enumerate().map(|(i, &t)| (t, i)).collect();

    // The committed timeline, then one view per in-flight writer.
    let mut views: Vec<Option<TxnId>> = Vec::with_capacity(1 + writers.len());
    views.push(None);
    views.extend(writers.iter().copied().map(Some));

    let k = per_key.len();
    let mut out: Vec<Vec<Value>> = Vec::new();
    // Hashed dedup: bucket -> positions in `out`. Membership is decided by the exact `==` confirm, so a
    // coarse hash only ever costs extra comparisons; the output is the same distinct set as before.
    let mut seen: HashMap<u64, Vec<usize>> = HashMap::new();
    // Reused union-find scratch for the newest-priority interval fill (length `n + 1`).
    let mut next: Vec<usize> = Vec::with_capacity(n + 1);

    for &writer in &views {
        let owner = writer.unwrap_or(TxnId(0)); // `TxnId(0)` is never a writer: a "no own writes" owner.
        // For each key, the value the reader at THIS view resolves at each instant (newest-visible
        // wins). `found[key][i]` = the newest version covering instant `i` (its value may be NULL — an
        // absent key at assembly), or `None` if no version covers `i`.
        let mut found: Vec<Vec<Option<&Value>>> = Vec::with_capacity(k);
        for versions in per_key {
            let mut col: Vec<Option<&Value>> = vec![None; n];
            // Reset the "next empty" cursor: every slot starts empty (`next[i] == i`).
            next.clear();
            next.extend(0..=n);
            // Newest-first so a newer version claims a shared instant; older versions fill only the gaps.
            for &v in versions {
                let Some((lo, hi)) =
                    visible_instant_range(v, owner, registry, &instants, &instant_index)?
                else {
                    continue; // visible at no instant from this view
                };
                let mut i = uf_next_empty(&mut next, lo);
                while i < hi {
                    col[i] = Some(&v.value);
                    next[i] = i + 1; // mark filled -> skip on the next lookup
                    i = uf_next_empty(&mut next, i + 1);
                }
            }
            found.push(col);
        }

        // Assemble one tuple per instant: the newest-visible value of every key, all present and
        // non-null. A key whose newest-visible version is absent or NULL makes the tuple incomplete
        // (Cypher's treatment of NULL in an index key), so the entity contributes nothing at that view.
        for i in 0..n {
            let mut tuple = Vec::with_capacity(k);
            let mut complete = true;
            for col in &found {
                match col[i] {
                    Some(value) if !value.is_null() => tuple.push(value.clone()),
                    _ => {
                        complete = false;
                        break;
                    }
                }
            }
            if complete {
                let bucket = seen.entry(composite_tuple_hash(&tuple)).or_default();
                if !bucket.iter().any(|&j| out[j] == tuple) {
                    bucket.push(out.len());
                    out.push(tuple);
                }
            }
        }
    }
    Ok(out)
}

/// The **in-flight** (unresolved) transaction holding the NEWEST version of some `covered` property
/// key of this entity, if any, given its property `chain` newest-first (from
/// [`RecordStore::node_properties`](graphus_storage::RecordStore::node_properties) /
/// [`rel_properties`](graphus_storage::RecordStore::rel_properties)) and the commit `registry`
/// (`rmp` task #778; reusable for the spatial #779 / vector #780 trees, which share this build shape).
///
/// # Why the single-value-per-entity trees need this (option (b), poison-on-build)
///
/// Full-text, spatial and vector indexes build **newest-wins**: one term-set / point / embedding per
/// entity. If such an index is (re)built while the newest version of a covered property is an active
/// writer's *uncommitted* overwrite, that dirty value is baked and the committed value is indexed
/// **nowhere** — the #766 loss — and the consumer cannot repair it: `fulltext_query` re-checks a
/// candidate's visibility + current label but NOT its terms (#773 measured that a version-union there
/// returns WRONG ROWS). So when this predicate holds the build must **not** promote the index to
/// `Online`; it stays `Populating`, and every reader declines to the snapshot-correct scan fallback until
/// the writer commits or aborts. Once it resolves the newest version is either the writer's now-committed
/// value or (on abort) the restored committed version, and the build rebuilds and promotes cleanly.
///
/// # Why not option (a), and what was actually measured
///
/// Option (a) — teach `fulltext_query` to re-analyze each candidate's snapshot-visible covered text and
/// confirm the search terms match — would make a version-union sound, because the extra terms would then
/// be false positives the consumer drops (exactly how the #773 TEXT/trigram fix works). It is **not**
/// ruled out on cost: measured on a 4 000-node corpus (`rmp` #778 AC 2), seek + per-candidate re-check
/// costs 0.04x the scan fallback at 1% candidate selectivity, 0.13x at 10%, 0.52x at 50% and 1.02x in the
/// degenerate case where every node is a candidate — i.e. it is never materially worse than the scan it
/// would replace, because the scan already re-analyzes *every* entity while the re-check touches only
/// candidates. Any earlier claim that option (a) is "prohibitively costly" was never measured and is
/// contradicted by those numbers.
///
/// Option (b) is chosen here on **scope**, not cost: a union would also pollute the forward map that
/// `fulltext_score` / `fulltext_score_rel` read for relevance, so option (a) is a three-part change
/// (build union + consumer term re-check + score recomputation) that must additionally be mirrored on the
/// off-thread reader seam to keep `read_only_graph`'s answers byte-identical to the inline path. Option
/// (b) is contained entirely in the build drivers and costs only DDL liveness — an index covering a
/// property under uncommitted mutation serves the (correct) scan until that writer resolves.
///
/// # Correctness of the stamp resolution
///
/// A raw `InFlight(w)` stamp does NOT mean `w` is running: commit stamps settle **lazily**, so a
/// long-committed version still reads `InFlight(w)` until a GC pass freezes it. The liveness question is
/// therefore asked of the store's Active Transaction Table via
/// [`RecordStore::is_txn_active`](graphus_storage::RecordStore::is_txn_active) — deliberately NOT
/// `CommitRegistry::outcome(w) == TxnOutcome::InFlight`, which is **dead, always false** (the registry
/// gains an entry only when a transaction *resolves*, and an unknown id maps to `Aborted`). That exact
/// confusion is `rmp` #522, and re-making it here would have made this whole gate a no-op.
///
/// An **aborted** writer's version is orphaned from the chain head on rollback (the `write_chain_head`
/// CAS undo in `graphus-storage`), so it is never the newest a chain walk returns — the newest is
/// therefore always either committed or held by a still-active writer, and this predicate is exact for
/// the #766 overwrite window. (A concurrent *delete* of the newest version — `xmax` in-flight — is a
/// distinct, narrower window not covered here.)
///
/// # Errors
/// Propagates a stamp-resolution fault from the [`CommitOracle`] door (`rmp` #1069). An
/// unresolvable stamp must fail the build, never read as "no active writer" — that answer promotes
/// the index to `Online` over a value nobody verified, which is the whole hole this gate closes.
fn active_writer_holds_newest_covered(
    chain: &[(u64, PropRecord)],
    covered: &[u32],
    registry: &CommitRegistry,
    is_active: impl Fn(TxnId) -> bool,
) -> Result<Option<TxnId>> {
    // `names_writer`, NOT `resolve_stamp`: the door's `InFlight` arm is dead through the registry
    // (an unresolved writer maps to `Aborted`), so asking the OUTCOME here would make this whole gate
    // a no-op — the exact `rmp` #522 / #778 defect the doc above warns about. The identity comes
    // from the word; the liveness from the store's Active Transaction Table via `is_active`.
    let held_by_active = |word: u64| -> Result<Option<TxnId>> {
        Ok(registry.names_writer(word)?.filter(|w| is_active(*w)))
    };
    for &key in covered {
        // Newest-first: the FIRST occurrence of `key` in the chain is its newest version.
        let Some((_, prop)) = chain.iter().find(|(_, prop)| prop.key == key) else {
            continue;
        };
        // BOTH MVCC stamps, because before `rmp` #967 each half of an uncommitted change hid
        // behind a different one. `created_ts` caught `SET n.p = …` (the writer PREPENDED a new
        // version, so its dirty value was the chain head); `expired_ts` caught `REMOVE n.p` (the
        // writer TOMBSTONED in place WITHOUT prepending, so the head was still the committed
        // record and only its expiry stamp named the writer). Checking `created_ts` alone left
        // the removal half of this window open — MEASURED: the build baked the doomed value, and
        // once the removal committed the index kept matching a term the entity no longer has.
        //
        // After `rmp` #967 BOTH halves restamp `created_ts` of the SAME cell: a `SET` rewrites it
        // in place and a `REMOVE` empties it in place (`D-property-removal`), and a property
        // operation never writes `expired_ts` again. So `created_ts` alone would now suffice and
        // `expired_ts` is always `0` here; the second probe is kept because it costs one compare
        // against a word that is now invariantly zero and it fails closed against any older store
        // image (or any future path) that still carries an expiry stamp on a property cell.
        // Two sequential probes rather than `a.or(b)`: `or` is eager, and evaluating the second
        // probe after the first already answered would surface an oracle fault the pre-#1069
        // `or_else` never reached. The short-circuit is preserved exactly.
        if let Some(w) = held_by_active(prop.mvcc.created_ts)? {
            return Ok(Some(w));
        }
        if let Some(w) = held_by_active(prop.mvcc.expired_ts)? {
            return Ok(Some(w));
        }
    }
    Ok(None)
}

/// One candidate value of one property together with the **validity interval** the composite build
/// needs, reconstructed from the entity's undo chain (`rmp` #967).
///
/// The stamps are raw [`VersionStamp`] words in exactly the encoding
/// [`visible_instant_range`] resolves, so a `StampedCandidate` is a drop-in for the pre-#967
/// `PropRecord` + `MvccHeader` pair the composite sweep used to read.
struct StampedCandidate {
    key: u32,
    type_tag: u8,
    value_inline: u64,
    /// Stamp of the transaction that INSTALLED this value.
    xmin: u64,
    /// Stamp of the transaction that REPLACED it; `0` = still current.
    xmax: u64,
}

/// The **superset** of one entity's property values with each value's validity interval —
/// the composite-index build's read after the property path moved onto the undo chain (`rmp` #967).
///
/// # Why the intervals have to be reconstructed rather than dropped
///
/// [`SupersetProperties::candidates`] is the plain superset: every value the entity holds or has
/// held, with no stamps. That is exactly right for a structure that indexes each value
/// independently (text, spatial), but a **composite** index indexes *tuples*, and a tuple is only
/// observable if its members were current **at one common instant**. Handing the sweep a stampless
/// candidate set would leave only two options, both bad: collapse to one value per key, which drops
/// every tuple an older snapshot needs (the `rmp` #766 / #683 loss — a missing NODE KEY candidate
/// makes the write path's duplicate check find nothing and ADMIT a committed duplicate), or emit the
/// Cartesian product of the per-key candidate sets, which is `O(V^k)` where the interval
/// construction is `O(V)` (see [`composite_candidate_tuples`], whose whole `rmp` #774 rework exists
/// to keep that term linear).
///
/// So this rebuilds the intervals from the chain, which loses nothing: an entity holds exactly one
/// value per key at any instant, so the observable tuples are still precisely the per-instant ones.
///
/// # The reconstruction rule
///
/// A `SetProperty` delta carries the value the key held **before** the write that pushed it, so on a
/// chain read newest-first (`d1`, `d2`, … with commit stamps `S1 >= S2 >= …`, the ordering the
/// entity-granularity conflict check `D-property-write-conflict` guarantees and the consistency
/// checker re-verifies):
///
/// * the **live cell**'s value was installed by `d1`'s writer and is current, so `(xmin, xmax) =
///   (cell.created_ts, 0)` — every write restamps the cell's `created_ts` in place, so that word is
///   the installing writer's stamp even though the value itself is written in place;
/// * `d_i`'s value was installed by `d_{i+1}`'s writer and ended when `d_i`'s writer committed, so
///   `(xmin, xmax) = (S_{i+1}, S_i)`;
/// * the **oldest** retained delta for a key has no `S_{i+1}` on the chain — the write that
///   installed its value has already been reclaimed — so `xmin` falls back to `entity_created_ts`,
///   a stamp that is always a lower bound for any value the entity ever held. That widens the
///   interval, which is the safe direction: the sweep fills instants newest-first, so a wider older
///   interval can only paint instants no newer version claimed. Extra tuples are false positives a
///   seek's re-check drops; a missing one is unrecoverable.
///
/// Corpse deltas and deltas whose commit slot is a corpse are skipped entirely (their transaction
/// aborted, so neither their value nor their stamp ever bounded anything) — the same rule
/// [`SupersetProperties::candidates`] applies, kept identical here on purpose.
fn stamped_candidates(chain: &SupersetProperties, entity_created_ts: u64) -> Vec<StampedCandidate> {
    let cells = chain.cells_ignoring_history();
    let mut out: Vec<StampedCandidate> = Vec::with_capacity(cells.len() + chain.history_len());
    let mut seen_keys: Vec<u32> = Vec::with_capacity(cells.len());
    for &(_pid, cell) in cells {
        if seen_keys.contains(&cell.key) {
            // A healthy post-#967 store holds ONE cell per key (the checker reports a second as a
            // fault); resolving to the chain head keeps an older store image readable rather than
            // doubling the key.
            continue;
        }
        seen_keys.push(cell.key);
        if cell.type_tag == TYPE_TAG_ABSENT {
            continue; // the key is currently absent — no value, but its history may still hold some
        }
        out.push(StampedCandidate {
            key: cell.key,
            type_tag: cell.type_tag,
            value_inline: cell.value_inline,
            xmin: cell.mvcc.created_ts,
            xmax: 0,
        });
    }
    // `pending[i] = (key, index into out)`: a delta-sourced value whose `xmin` is still the
    // `entity_created_ts` fallback and will be corrected by the next older write of the same key.
    let mut pending: Vec<(u32, usize)> = Vec::new();
    for entry in chain.history() {
        if !entry.delta.in_use() {
            continue; // a corpse: its transaction aborted, so this write never happened
        }
        let Some(slot) = entry.slot.filter(|s| s.in_use()) else {
            continue; // an unresolvable or aborted writer — same treatment as a corpse delta
        };
        if entry.delta.action != UndoAction::SetProperty {
            continue; // changes no property (it still participates in the chain's ordering)
        }
        let key = entry.delta.token;
        // This delta's writer INSTALLED the value recorded above it for `key`.
        if let Some(pos) = pending.iter().position(|(k, _)| *k == key) {
            let (_, idx) = pending.remove(pos);
            out[idx].xmin = slot.commit_ts;
        }
        if entry.delta.type_tag == TYPE_TAG_ABSENT {
            // "the key was absent before this write": no candidate value, but the bound it just set
            // on the value above it is real.
            continue;
        }
        out.push(StampedCandidate {
            key,
            type_tag: entry.delta.type_tag,
            value_inline: entry.delta.value_inline,
            xmin: entity_created_ts,
            xmax: slot.commit_ts,
        });
        pending.push((key, out.len() - 1));
    }
    out
}

/// Equivalence guard for the `rmp` #774 merge-sweep: `composite_candidate_tuples` must produce the SAME
/// candidate SET as the pre-#774 `find`-per-instant construction, for ANY chain — a wrong tuple here is a
/// dropped candidate, i.e. an admitted committed duplicate on a NODE KEY / REL KEY (`rmp` #683 / #765).
/// The oracle below is that former construction, verbatim in shape (per-instant `graphus_txn::is_visible_via`
/// + `Vec::contains` dedup), so the two agreeing pins the sweep to the exact semantics it replaced.
#[cfg(test)]
mod composite_sweep_equivalence {
    use super::*;
    use graphus_core::VersionStamp;

    /// The in-memory registry never faults, so the oracle below keeps its infallible shape and every
    /// assertion in this module is unchanged; only the `?`-shaped calls into the `rmp` #1069 door are
    /// new. A fault here would be a bug in the door itself, so it panics rather than being folded in.
    fn expect<T>(r: Result<T>) -> T {
        r.expect("the in-memory commit registry resolves every stamp")
    }

    /// The pre-#774 construction: one tuple per (view, instant) via a linear `find`, deduped by
    /// structural `PartialEq`. This is the reference the sweep must match, so it is intentionally the
    /// slow, obviously-correct shape.
    fn oracle(per_key: &[Vec<&PropVersion>], registry: &CommitRegistry) -> Vec<Vec<Value>> {
        let mut instants: Vec<Timestamp> = vec![Timestamp(0)];
        let mut writers: Vec<TxnId> = Vec::new();
        for versions in per_key {
            for v in versions {
                for raw in [v.xmin, v.xmax] {
                    match expect(registry.resolve_commit_ts(raw)) {
                        Some(ts) => {
                            if !instants.contains(&ts) {
                                instants.push(ts);
                            }
                        }
                        None => {
                            if let Some(w) = expect(registry.names_writer(raw))
                                && !writers.contains(&w)
                            {
                                writers.push(w);
                            }
                        }
                    }
                }
            }
        }
        let mut views: Vec<Option<TxnId>> = vec![None];
        views.extend(writers.into_iter().map(Some));

        let mut out: Vec<Vec<Value>> = Vec::new();
        for writer in views {
            let owner = writer.unwrap_or(TxnId(0));
            for &t in &instants {
                let mut tuple = Vec::with_capacity(per_key.len());
                let mut complete = true;
                for versions in per_key {
                    match versions
                        .iter()
                        .find(|v| {
                            expect(graphus_txn::is_visible_via(
                                registry,
                                Snapshot::new(owner, t),
                                v.xmin,
                                v.xmax,
                            ))
                        })
                        .map(|v| &v.value)
                        .filter(|v| !v.is_null())
                    {
                        Some(value) => tuple.push(value.clone()),
                        None => {
                            complete = false;
                            break;
                        }
                    }
                }
                if complete && !out.contains(&tuple) {
                    out.push(tuple);
                }
            }
        }
        out
    }

    /// Asserts the sweep and the oracle emit the same SET of tuples (order-independent, both deduped).
    fn assert_same_set(per_key: &[Vec<&PropVersion>], registry: &CommitRegistry) {
        let got = composite_candidate_tuples(per_key, registry)
            .expect("the in-memory commit registry resolves every stamp");
        let want = oracle(per_key, registry);
        let subset =
            |a: &[Vec<Value>], b: &[Vec<Value>]| a.iter().all(|x| b.iter().any(|y| x == y));
        assert!(
            got.len() == want.len() && subset(&got, &want) && subset(&want, &got),
            "sweep != oracle\n sweep = {got:?}\noracle = {want:?}",
        );
    }

    fn pv(xmin: u64, xmax: u64, value: i64) -> PropVersion {
        PropVersion {
            xmin,
            xmax,
            value: Value::Integer(value),
        }
    }

    /// A committed-only chain (the dominant real case): three settled versions, no writer.
    #[test]
    fn committed_only_chain() {
        let reg = CommitRegistry::new();
        let cm = VersionStamp::committed;
        // newest-first: v3 live [30,inf), v2 [20,30), v1 [10,20)
        let v3 = pv(cm(Timestamp(30)), 0, 3);
        let v2 = pv(cm(Timestamp(20)), cm(Timestamp(30)), 2);
        let v1 = pv(cm(Timestamp(10)), cm(Timestamp(20)), 1);
        assert_same_set(&[vec![&v3, &v2, &v1]], &reg);
    }

    /// A committed-then-deleted property: the newest version expires, so late snapshots see NOTHING and
    /// the tuple is incomplete (found -> none, not resurrect-older).
    #[test]
    fn committed_then_deleted() {
        let reg = CommitRegistry::new();
        let cm = VersionStamp::committed;
        let v2 = pv(cm(Timestamp(20)), cm(Timestamp(40)), 2); // created 20, deleted 40
        let v1 = pv(cm(Timestamp(10)), cm(Timestamp(20)), 1);
        assert_same_set(&[vec![&v2, &v1]], &reg);
    }

    /// THE in-flight-writer overlap the naive monotone cursor gets wrong (`rmp` #774): writer `w`'s own
    /// live write is visible at EVERY instant, overlapping the older committed versions it superseded, so
    /// `w`'s view resolves `w`'s value at every instant while the committed view walks the older chain.
    #[test]
    fn in_flight_writer_overlaps_committed_chain() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(9)); // w = 9, in flight
        let cm = VersionStamp::committed;
        let inflight = VersionStamp::in_flight;
        // newest-first: v0 = w's own live write; v1 committed then superseded by w; v2 older committed.
        let v0 = pv(inflight(TxnId(9)), 0, 100);
        let v1 = pv(cm(Timestamp(20)), inflight(TxnId(9)), 2);
        let v2 = pv(cm(Timestamp(10)), cm(Timestamp(20)), 1);
        assert_same_set(&[vec![&v0, &v1, &v2]], &reg);
    }

    /// A version whose creator LAZILY committed (header still reads `InFlight`, registry says committed):
    /// its real commit instant must come from the registry, not the raw word.
    #[test]
    fn lazily_stamped_commit_resolves_via_registry() {
        let mut reg = CommitRegistry::new();
        reg.record_commit(TxnId(5), Timestamp(25)); // committed but header still InFlight(5)
        let inflight = VersionStamp::in_flight;
        let cm = VersionStamp::committed;
        let v2 = pv(inflight(TxnId(5)), 0, 2); // lazily-stamped, live
        let v1 = pv(cm(Timestamp(10)), inflight(TxnId(5)), 1); // superseded by the lazily-stamped txn
        assert_same_set(&[vec![&v2, &v1]], &reg);
    }

    /// Two keys with independent chains + a NULL that makes a tuple incomplete at some instants.
    #[test]
    fn two_keys_with_null_hole() {
        let reg = CommitRegistry::new();
        let cm = VersionStamp::committed;
        let ka2 = pv(cm(Timestamp(30)), 0, 5);
        let ka1 = pv(cm(Timestamp(10)), cm(Timestamp(30)), 4);
        let kb2 = pv(cm(Timestamp(20)), 0, 7);
        // A NULL newest version on key b before 20 -> incomplete there.
        let kb1 = PropVersion {
            xmin: cm(Timestamp(5)),
            xmax: cm(Timestamp(20)),
            value: Value::Null,
        };
        assert_same_set(&[vec![&ka2, &ka1], vec![&kb2, &kb1]], &reg);
    }

    /// The construction must scale SUB-QUADRATICALLY in the version-chain length `V` (`rmp` task #774).
    /// This is the sharp, load-invariant guard for the merge-sweep: it times the construction ALONE (no
    /// store reads / tree inserts to dilute it) at 4x apart sizes and asserts the time ratio is far below
    /// a quadratic's. A ratio gate cancels any uniform machine slowdown, so it does not flap on load —
    /// what changes under a regression is the *shape*, not the constant. Measured: the linear sweep is
    /// ~4.2x per 4x step (exponent ~1.0); the pre-#774 `find`-per-instant construction was ~15.6x
    /// (exponent ~2.0). The `< 9.0` ceiling passes the former with ~2x margin and fails the latter.
    #[test]
    fn construction_scales_sub_quadratically() {
        // A clean 3-key committed chain of `v` versions (one node updated `v` times), newest-first.
        fn chains(v: usize) -> Vec<Vec<PropVersion>> {
            let cm = VersionStamp::committed;
            (0..3)
                .map(|_| {
                    (0..v)
                        .map(|j| PropVersion {
                            // j=0 is newest+live at V*10; j>=1 created (V-j)*10, expired (V-j+1)*10.
                            xmin: cm(Timestamp(((v - j) as u64) * 10)),
                            xmax: if j == 0 {
                                0
                            } else {
                                cm(Timestamp(((v - j + 1) as u64) * 10))
                            },
                            value: Value::Integer((v - j) as i64),
                        })
                        .collect()
                })
                .collect()
        }
        // Min of a few runs: least-noisy estimator of the intrinsic cost.
        fn min_nanos(store: &[Vec<PropVersion>], reg: &CommitRegistry) -> u128 {
            let per_key: Vec<Vec<&PropVersion>> =
                store.iter().map(|c| c.iter().collect()).collect();
            (0..5)
                .map(|_| {
                    let t = std::time::Instant::now();
                    std::hint::black_box(composite_candidate_tuples(&per_key, reg).unwrap());
                    t.elapsed().as_nanos()
                })
                .min()
                .unwrap()
        }
        let reg = CommitRegistry::new();
        let small = chains(256);
        let large = chains(1024); // 4x
        // Warm up so the ratio reflects steady state, not first-touch allocation.
        let _ = min_nanos(&small, &reg);
        let t_small = min_nanos(&small, &reg);
        let t_large = min_nanos(&large, &reg);
        let ratio = t_large as f64 / t_small.max(1) as f64;
        assert!(
            ratio < 9.0,
            "composite construction regressed toward quadratic: 4x more versions took {ratio:.1}x \
             longer (linear sweep is ~4x; the pre-#774 quadratic was ~16x). \
             t(256)={t_small}ns t(1024)={t_large}ns",
        );
    }

    /// Deterministic randomized battery over arbitrary chains, registries and views. Both functions
    /// derive from the same visibility rules, so they must agree on ANY input — this exercises far more
    /// shapes (aborted, foreign in-flight, lazy commits, multi-writer overlaps) than the hand cases.
    #[test]
    fn randomized_battery_agrees() {
        // xorshift64* — dependency-free deterministic PRNG.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        for _ in 0..4000 {
            let mut reg = CommitRegistry::new();
            // A pool of up to 6 transactions, each committed / aborted / left in flight.
            let n_txn = 1 + rng() % 6;
            let mut committed: Vec<(TxnId, Timestamp)> = Vec::new();
            let mut inflight_ids: Vec<TxnId> = Vec::new();
            for id in 1..=n_txn {
                let txn = TxnId(id);
                match rng() % 3 {
                    0 => {
                        let ts = Timestamp(1 + rng() % 40);
                        reg.record_commit(txn, ts);
                        committed.push((txn, ts));
                    }
                    1 => {
                        reg.register_begin(txn);
                        inflight_ids.push(txn);
                    }
                    _ => reg.record_abort(txn),
                }
            }
            // A raw stamp word: 0 (none/live), a settled commit, a lazy commit or in-flight (header
            // InFlight), or a foreign committed timestamp not in the pool.
            let raw_word = |rng: &mut dyn FnMut() -> u64| -> u64 {
                match rng() % 4 {
                    0 => 0,
                    1 => VersionStamp::committed(Timestamp(1 + rng() % 40)),
                    2 if !committed.is_empty() => {
                        // Header reads InFlight but the registry has it committed (lazy) — or settled.
                        let (txn, ts) = committed[(rng() % committed.len() as u64) as usize];
                        if rng() % 2 == 0 {
                            VersionStamp::in_flight(txn)
                        } else {
                            VersionStamp::committed(ts)
                        }
                    }
                    _ if !inflight_ids.is_empty() => VersionStamp::in_flight(
                        inflight_ids[(rng() % inflight_ids.len() as u64) as usize],
                    ),
                    _ => VersionStamp::committed(Timestamp(1 + rng() % 40)),
                }
            };

            let n_keys = 1 + (rng() % 3) as usize;
            let mut chains: Vec<Vec<PropVersion>> = Vec::with_capacity(n_keys);
            for _ in 0..n_keys {
                let chain_len = (rng() % 5) as usize; // 0..=4 (0 exercises the empty-key skip too)
                let mut chain = Vec::with_capacity(chain_len);
                for _ in 0..chain_len {
                    let xmin = raw_word(&mut rng);
                    let xmax = raw_word(&mut rng);
                    // A small value domain forces genuine collisions so the dedup is exercised; an
                    // occasional NULL exercises the incomplete-tuple path.
                    let value = match rng() % 5 {
                        0 => Value::Null,
                        v => Value::Integer((v % 3) as i64),
                    };
                    chain.push(PropVersion { xmin, xmax, value });
                }
                chains.push(chain);
            }
            // Skip inputs with an empty key chain: the callers filter those out before calling, and both
            // functions treat an empty `per_key[i]` identically (no version -> all tuples incomplete),
            // but the contract is "every key has >= 1 version".
            if chains.iter().any(Vec::is_empty) {
                continue;
            }
            let per_key: Vec<Vec<&PropVersion>> =
                chains.iter().map(|c| c.iter().collect()).collect();
            assert_same_set(&per_key, &reg);
        }
    }
}
use graphus_index::fulltext::Analyzer;
use graphus_index::histogram::PropertyHistogram;
use graphus_index::keycodec::encode_equality_canonical;
use graphus_index::{Similarity, VectorIndexError};
use graphus_io::BlockDevice;
use graphus_storage::undo::{TYPE_TAG_ABSENT, UndoAction};
use graphus_storage::{
    CompositeIndexEntry, ConstraintEntry, ConstraintKind, ConstraintTypeDescriptor, DeadIndexKey,
    DecidedProperties, FulltextEntity, FulltextIndexEntry, GcPassReport, IndexInterest, IndexState,
    Namespace, PropRecord, RecordStore, RelCompositeIndexEntry, SpatialEntity, SpatialIndexEntry,
    StoreKind, StoreReadView, SupersetProperties, TextIndexEntry, TokenSnapshot, VectorEntity,
    VectorIndexEntry, VectorSimilarity,
};
use graphus_txn::{
    CommitOracle, CommitRegistry, IsolationLevel, PredicateRead, Snapshot, SsiReadBuffer,
    SsiTracker, is_visible_via,
};
use graphus_wal::LogSink;

use crate::catalog::IndexCatalog;
use crate::constraint::{ConstraintViolation, ViolationEntity};
use crate::executor::CancellationToken;
use crate::index_set::{DeadKeyCollection, DeadKeyEvidence, IndexSet, IndexWriter};
use crate::record_graph::RecordStoreGraph;
use crate::schema_error::{
    constraint_name_in_use, equivalent_composite_index_exists, equivalent_constraint_exists,
    equivalent_index_exists, equivalent_rel_composite_index_exists, equivalent_rel_index_exists,
    index_drop_not_found, index_name_in_use,
};
use crate::statistics::Statistics;

/// One row of [`TxnCoordinator::list_fulltext_indexes`] (`rmp` tasks #72, #663): the index name, its
/// [`FulltextEntity`], its covered labels/types (one or more), its covered properties, its analyzer and
/// its build state — the tuple a `SHOW FULLTEXT INDEXES` surface renders.
pub type FulltextIndexListing = (
    String,
    FulltextEntity,
    Vec<String>,
    Vec<String>,
    Analyzer,
    IndexState,
);

/// One row of [`TxnCoordinator::list_vector_index_listings`] (`rmp` task #671): every field a
/// `SHOW INDEXES` VECTOR row needs — the index name, its [`VectorEntity`], its covered label / type,
/// its covered embedding property, the embedding `dimensions`, the [`VectorSimilarity`] metric, the
/// HNSW `m` / `ef_construction` build parameters and its build state.
///
/// Unlike the thinner [`TxnCoordinator::list_vector_indexes`] tuple (`(name, label, property, state)`,
/// `rmp` #669), this carries the full `indexConfig` so the unified index listing can render the
/// `options` map and a round-trippable `createStatement`. A struct (rather than a wide tuple) keeps the
/// nine fields self-documenting at every use site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorIndexListing {
    /// The server-unique index name.
    pub name: String,
    /// Whether the index covers a node label or a relationship type.
    pub entity: VectorEntity,
    /// The covered node label ([`Node`](VectorEntity::Node)) or relationship type
    /// ([`Relationship`](VectorEntity::Relationship)).
    pub label_or_type: String,
    /// The covered embedding property (exactly one).
    pub property: String,
    /// The embedding dimension (`> 0`).
    pub dimensions: u32,
    /// The similarity metric the HNSW graph navigates by.
    pub similarity: VectorSimilarity,
    /// The HNSW `m` build parameter (target out-degree per layer).
    pub m: u32,
    /// The HNSW `ef_construction` build parameter (construction candidate-list size).
    pub ef_construction: u32,
    /// The build state of the index.
    pub state: IndexState,
}
use crate::store_statistics;

/// Renders a [`Value`] compactly for a constraint-violation message (`rmp` task #99): a string is
/// single-quoted, everything else uses its `Debug` form. Kept small and side-effect-free — this is
/// only for the human message, never for comparison or persistence.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(s) => format!("'{s}'"),
        other => format!("{other:?}"),
    }
}

/// Renders a composite-tuple value list as `(v1, v2, …)` for a node-key violation message (`rmp` task
/// #100), reusing [`render_value`] per element.
fn render_tuple(values: &[Value]) -> String {
    let inner = values
        .iter()
        .map(render_value)
        .collect::<Vec<_>>()
        .join(", ");
    format!("({inner})")
}

/// Whether two composite tuples are equal by **Cypher value equality**, element-wise (`rmp` task
/// #100). Used to detect a node-key duplicate; the tuples always have equal length (the same covered
/// property count). A null element would make the tuple incomplete and never reach here.
fn tuples_equal(a: &[Value], b: &[Value]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| crate::equality::equals(x, y).is_true())
}

/// The covered value tuples a uniqueness walk has already inspected, indexed so that deciding whether
/// the next entity duplicates one of them costs **O(1) expected** instead of O(entities) (`rmp` task
/// #956).
///
/// Both constraint walks used to keep the inspected values in a plain `Vec` and search it with
/// [`tuples_equal`] per entity, which made `CREATE CONSTRAINT … IS UNIQUE` quadratic in the number of
/// entities carrying the covered token: measured over distinct string values, 42.94 s for 100 000
/// nodes against 0.381 s for 10 000 — a fitted exponent of 2.05 — where this set makes the same walk
/// 1.159 s and 0.110 s, an exponent of 1.02
/// (`graphus-cypher`'s `tests/constraint_validation_scaling_956.rs`). Since `rmp` task #903 the walk is
/// a registered transaction holding a snapshot, so its duration is exactly the window in which it pins
/// the GC watermark: a quadratic walk blocks reclamation on a live database for a quadratic time, which
/// turns a latency defect into an availability one.
///
/// The construction is the one already used for this exact shape by `aggregate_rows` (`rmp` #314) and
/// `hash_join_rows` (`rmp` #865): bucket by a digest, then resolve *inside* the bucket with the
/// authoritative relation.
///
/// # The hash buckets; only [`tuples_equal`] decides
///
/// Cypher value equality is not Rust's `Eq`, so a `HashSet<Value>` would be a different — wrong —
/// relation. `1 = 1.0` is `TRUE` across `INTEGER`/`FLOAT`, and above 2^53 the comparison is *exact*,
/// so `9007199254740993 = 9007199254740992.0` is `FALSE` even though the first rounds to the second in
/// `f64` (`rmp` task #894). The digest therefore only ever chooses a bucket; the accept/refuse decision
/// stays with [`tuples_equal`], i.e. with [`crate::equality::equals`], exactly as before this task.
///
/// # Why equal values are guaranteed to share a bucket
///
/// The soundness obligation is one-directional and total: whenever `equals(a, b)` is `TRUE`, `a` and
/// `b` **must** hash alike, or the walk could file a duplicate in a bucket where the probe never looks
/// and accept a constraint the data violates. A collision in the other direction costs nothing — two
/// unequal values sharing a bucket are separated by [`tuples_equal`].
///
/// [`crate::equivalence::hash_value`] discharges that obligation. It is documented consistent with
/// [`crate::equivalence::equivalent`] (equivalent values hash alike), and definite equality is a
/// *subset* of equivalence: the two relations differ only on `null` (`null ≡ null` but `null = null`
/// is `NULL`) and on `NaN` (`NaN ≡ NaN` but `NaN = NaN` is `FALSE`) — neither of which is ever
/// `Ternary::True`, so no pair `equals` calls equal escapes equivalence. Case by case that means
/// `INTEGER` and `FLOAT` share one hash class (`1` and `1.0` collide, as they must), signed zeros are
/// normalised, temporals hash through their derived `Hash` (consistent with the derived `PartialEq`
/// their equality uses), points hash CRS-then-coordinates like [`graphus_core::Point::value_eq`]
/// compares them, and lists/maps recurse — maps order-independently, matching a map equality that
/// ignores key order. The `rmp` #894 pair lands in the *safe* direction: `hash_value` projects an
/// integer through `f64` and is therefore deliberately **coarser** than equality above 2^53, so
/// `9007199254740993` and `9007199254740992.0` share a bucket and are then correctly told apart by
/// [`tuples_equal`]. Coarser is always sound here; only a *finer* hash could split an equal pair, which
/// is why the digest must not be narrowed as the equality relation is refined.
///
/// # Hash-flooding resistance
///
/// The digest is `std`'s `DefaultHasher` — SipHash-1-3 with a per-process random seed — because the
/// values being bucketed are client-derived property values (SEC-210 / CWE-407); a fixed-seed hasher
/// over them would let an attacker seed a label whose values all collide and restore the quadratic
/// walk on demand. The outer map is an [`rustc_hash::FxHashMap`] because its key is that digest, which
/// is already a SipHash output — re-hashing it under SipHash would be pure waste. This is the same
/// split `group_key_hash` makes, and for the same reason. The tuple length is mixed in first, so a
/// 1-tuple and a 2-tuple cannot collide trivially.
///
/// # The one residual, and why it is bounded
///
/// The numeric coarsening above is the single input shape that can still stack a bucket, since a
/// bucket is searched linearly: distinct `INTEGER`s that round to one double share a key, and no
/// random seed separates them (they must share a key, or `1 = 1.0` would break). It is **bounded**
/// rather than open-ended. A double in `[2^e, 2^(e+1))` has spacing `2^(e-52)`, and an `i64` reaches
/// only `e ≤ 62`, so at most `2^10` = 1024 distinct integers can ever collapse onto one double. The
/// worst case is therefore O(entities × 1024) comparisons — still linear in the corpus, with a
/// constant an attacker cannot raise — and it is reachable only by values deliberately packed above
/// 2^53. Every other value class goes through the seeded SipHash, where buckets cannot be stacked at
/// all.
struct SeenTuples {
    /// Every recorded tuple, in first-seen order.
    tuples: Vec<Vec<Value>>,
    /// Digest → the ordinals in `tuples` whose tuple hashes there. Normally singleton.
    index: rustc_hash::FxHashMap<u64, Vec<usize>>,
}

impl SeenTuples {
    /// An empty set.
    fn new() -> Self {
        Self {
            tuples: Vec::new(),
            index: rustc_hash::FxHashMap::default(),
        }
    }

    /// The bucketing digest of `tuple` (see the type docs for the invariant it must satisfy).
    ///
    /// Deliberately *not* required to agree with any other digest in the codebase — it is a private
    /// bucketing device of this set, so it can hash [`Value`]s directly instead of wrapping each in a
    /// `RowValue` the way `group_key_hash` must.
    fn digest(tuple: &[Value]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        tuple.len().hash(&mut h);
        for v in tuple {
            crate::equivalence::hash_value(v, &mut h);
        }
        h.finish()
    }

    /// Whether a tuple **Cypher-equal** to `tuple` has already been recorded.
    ///
    /// Probes one bucket and confirms every candidate in it with [`tuples_equal`], so the answer is
    /// identical to the linear scan this replaced — only the number of comparisons differs.
    fn contains_equal(&self, tuple: &[Value]) -> bool {
        self.index
            .get(&Self::digest(tuple))
            .is_some_and(|bucket| bucket.iter().any(|&i| tuples_equal(&self.tuples[i], tuple)))
    }

    /// Records `tuple` as seen. Call only after [`contains_equal`](Self::contains_equal) reported
    /// `false`; recording a duplicate would not corrupt the set, but the walk refuses the constraint
    /// before it can happen.
    fn record(&mut self, tuple: Vec<Value>) {
        let digest = Self::digest(&tuple);
        self.index
            .entry(digest)
            .or_default()
            .push(self.tuples.len());
        self.tuples.push(tuple);
    }
}

/// A declared constraint resolved to human-readable names, for the `SHOW CONSTRAINTS` surface
/// (`rmp` tasks #99, #100). Carries the covered label, the **whole** covered property tuple (one for a
/// non-composite kind, several for a node key), the [`ConstraintKind`] and (for a property-type
/// constraint) the declared [`ConstraintTypeDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintInfo {
    /// The server-unique constraint name.
    pub name: String,
    /// The covered node label.
    pub label: String,
    /// The covered properties, in declared order (one for `Unique`/`Existence`/`PropertyType`,
    /// one-or-more for a `NodeKey`).
    pub properties: Vec<String>,
    /// The constraint kind.
    pub kind: ConstraintKind,
    /// The declared value type of a [`ConstraintKind::PropertyType`] constraint, or [`None`] otherwise.
    pub type_descriptor: Option<ConstraintTypeDescriptor>,
}

/// Live state of an open transaction the coordinator drives.
#[derive(Debug, Clone, Copy)]
struct ActiveTxn {
    snapshot: Snapshot,
    isolation: IsolationLevel,
    /// The **monotonic**-clock reading (nanoseconds, `rmp` #395) captured at begin, or `None` when the
    /// transaction was opened through the clock-agnostic [`TxnCoordinator::begin`] (the TCK / unit
    /// tests — never age-reaped). The server's open path uses [`TxnCoordinator::begin_at`] to stamp it,
    /// so the maximum-transaction-age sweep ([`TxnCoordinator::aged_transactions`], `rmp` #477) can
    /// reap a transaction whose lifetime exceeds the configured cap — freeing the GC watermark
    /// ([`TxnCoordinator::oldest_active_snapshot`]) it would otherwise pin indefinitely.
    begin_nanos: Option<u64>,
}

/// Everything one constraint-validation walk needs to decide *what it sees* and *what it announces*
/// (`rmp` task #903) — bundled so the two already-long validator signatures do not grow two more
/// positional parameters.
///
/// The walk runs inside the constraint DDL's own first-class transaction, so it carries that
/// transaction's [`Snapshot`] (whose `owner` is the DDL transaction id, which is also the SIREAD
/// marker's subject) together with the covered token and constraint kind that decide the marker shape
/// (node `Label`/`Equality` versus relationship `RelType`/`RelEquality`).
#[derive(Debug, Clone, Copy)]
struct ConstraintWalkCtx<'a> {
    /// The DDL transaction's snapshot: what the walk may see, and whose id the markers are recorded
    /// under (`snapshot.owner`).
    snapshot: Snapshot,
    /// The constraint kind, which selects the node or the relationship marker family.
    kind: ConstraintKind,
    /// The covered token — a node-label token for the node kinds, a relationship-type token for the
    /// `Rel*` kinds.
    token: u32,
    /// The cancellation token an operator's `TERMINATE TRANSACTIONS` trips (`rmp` task #903). Polled
    /// once per entity, which is the only granularity that can interrupt an O(store) walk.
    cancel: &'a CancellationToken,
}

/// One in-progress **non-blocking** node-property index build (`rmp` task #91).
///
/// A build indexes the nodes captured in `snapshot` (the store's live node-id list at build
/// start), a bounded chunk at a time, advancing `cursor` until it reaches the end; the index is
/// then promoted to [`IndexState::Online`]. Nodes created *after* the snapshot, value changes,
/// and deletes are all handled outside this snapshot by [`RecordStoreGraph::reindex_node`] /
/// the candidate-set re-check (see [`TxnCoordinator::advance_index_builds`] for the full
/// consistency argument), so the snapshot only needs to cover the rows that already existed.
/// How many consecutive failures-to-progress a non-blocking index build tolerates before it is
/// **poisoned** (`rmp` task #733) — see [`PendingIndexBuild::stall`]. Generous enough that a transient
/// storage fault self-heals, small enough that a permanent one terminates promptly instead of spinning
/// the engine at 100% CPU.
const BUILD_STALL_BUDGET: u8 = 32;

/// The ceiling on the degraded-index rebuild backoff (`rmp` task #733), in attempts skipped between
/// probes. A repair rebuild is O(store) and runs **synchronously on the engine thread**, stalling every
/// query behind it, so a permanently-faulting store must not trigger one every couple of seconds. At the
/// engine's 2 ms idle tick this ceiling is ≈ 8.7 minutes between attempts; on a busy engine (where the
/// counter advances once per command) it is longer still. Counted in attempts, not wall-clock: the
/// coordinator must remain deterministic for DST and so never reads the clock.
const MAX_DEGRADED_RETRY_BACKOFF: u32 = 262_144;

/// The synthetic blocker a FAULTED vector re-fill records (`rmp` task #780).
///
/// A re-fill wipes the graph before repopulating it, so a fault mid-way leaves an index that is empty
/// or holed — precisely the state that must never be served. Recording this id keeps the index declining
/// to the exact scan (which is correct, just slower) instead of publishing the hole.
///
/// It is deliberately an id no real transaction can hold, so `RecordStore::is_txn_active` reports it
/// resolved and the very next drain re-attempts the repair. That is the intent: the fault may be
/// transient, and a permanently-faulting store then costs one bounded probe per backoff window rather
/// than pinning the index on the slow path forever.
const REFILL_FAULT_BLOCKER: TxnId = TxnId(u64::MAX);

/// How many [`DeadIndexKey`]s one witness batch decides (`rmp` #992).
///
/// The witness is the only unbounded allocation on the reclamation path: one entry per distinct
/// entity a batch names, each holding two `Vec`s and every DECODED value some index covers. A GC pass
/// is not bounded in entities — a batched `DETACH DELETE`, a retention sweep or the tail of a bulk
/// load reclaims them by the million, and the report budgets in `graphus_storage`
/// (`MAX_DEAD_ENTITY_KEYS` is 1 Mi) cap the *keys*, not the bytes their witness costs. Deciding a
/// slice at a time bounds the live witness to the batch instead of to the pass, which is what keeps
/// this affordable on the smallest target this project supports rather than only on a server.
///
/// The size is a memory bound, not a throughput knob: bigger batches save only the re-read of an
/// entity whose keys straddle two of them, and the GC emits an entity's keys together, so straddling
/// is already the exception.
const DEAD_KEY_EVIDENCE_BATCH: usize = 4096;

/// Lifetime totals of the GC-driven index collection (`rmp` #992) — see
/// [`TxnCoordinator::index_collection_totals`](TxnCoordinator#structfield.index_collection_totals).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexCollectionTotals {
    /// Value-keyed B+-tree entries actually removed.
    pub entries_removed: u64,
    /// Entities whose entity-keyed postings were purged on physical reclamation.
    pub entities_purged: u64,
    /// Dead keys kept because a live version still warrants them, or because nothing proved
    /// otherwise. Includes every key of an abandoned batch.
    pub keys_retained: u64,
    /// Batches abandoned whole by the concurrency gate. Nil while the engine has one writer.
    pub abandonments: u64,
}

/// The drains to skip before the next poisoned-build resurrection attempt, given how many consecutive
/// resurrections have already failed to complete (`rmp` task #733, B2). `2^(attempts-1)`, capped at
/// [`MAX_DEGRADED_RETRY_BACKOFF`]: the first re-poison waits 1 drain, then 2, 4, 8, …, so a build that
/// keeps hitting an unreadable page is retried ever-less-often — its resurrection *rate* decays
/// geometrically to zero, instead of spinning the engine every tick. `attempts == 0` never reaches here
/// (the first resurrection is immediate), but is handled defensively as no skip.
#[must_use]
fn poison_backoff(attempts: u32) -> u32 {
    if attempts == 0 {
        return 0;
    }
    let shift = (attempts - 1).min(31);
    (1u32 << shift).min(MAX_DEGRADED_RETRY_BACKOFF)
}

struct PendingIndexBuild {
    /// The label token the index is declared on.
    label_token: u32,
    /// The property-key token the index is declared on.
    prop_key: u32,
    /// The node-id list captured at build start (`store.scan_node_ids()`). Indexing walks this in
    /// order; a since-deleted id simply inserts a stale candidate (harmless — the re-check drops it).
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; the build is complete once `cursor >= snapshot.len()`.
    cursor: usize,
    /// The [`IndexSet::wipe_generation`] this build is indexing into (`rmp` task #733). If a
    /// `fail_closed` wipes the index set mid-build, the epoch changes and the build **re-takes its
    /// snapshot from the store and restarts from cursor 0** instead of resuming over an emptied tree.
    /// Resuming would index only the tail of the snapshot and then promote the index `Online` with a hole
    /// in it; restarting over the *original* snapshot would still lose every row written after the
    /// snapshot was taken, because the wipe destroyed those maintenance writes too.
    generation: u64,
    /// How many more times this build may fail to make final progress before it is **poisoned**
    /// (`rmp` task #733) — dropped un-promoted, leaving its index `Populating` and therefore never
    /// served. Decremented on a chunk that could not read a node, and on a promotion blocked by a
    /// degraded index set; refilled by any chunk that does make progress.
    ///
    /// It exists because Graphus assumes storage faults are **persistent** (checksum / torn page). A
    /// build that retries an unreadable chunk forever never advances its cursor, and
    /// `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()` — an infinite loop at
    /// 100% CPU, re-scanning the store on every iteration. A bounded budget keeps a *transient* fault
    /// self-healing while guaranteeing termination against a permanent one.
    stall: u8,
}

/// One in-progress **non-blocking** full-text index build (`rmp` task #72), the analogue of
/// [`PendingIndexBuild`] for the inverted index. Indexes the `snapshot` nodes a bounded chunk at a
/// time, then promotes the named full-text index to [`IndexState::Online`]. The same candidate-set
/// argument applies: writes after the snapshot are maintained by
/// [`RecordStoreGraph::reindex_node`] and deletes are dropped by the query-time re-check, so the
/// snapshot only needs to cover the rows that already existed at build start.
struct PendingFulltextBuild {
    /// The server-unique name of the full-text index being built.
    name: String,
    /// The node-id list captured at build start.
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; complete once `cursor >= snapshot.len()`.
    cursor: usize,
    /// The [`IndexSet::wipe_generation`] this build is indexing into (`rmp` task #733). If a
    /// `fail_closed` wipes the index set mid-build, the epoch changes and the build **re-takes its
    /// snapshot from the store and restarts from cursor 0** instead of resuming over an emptied tree.
    /// Resuming would index only the tail of the snapshot and then promote the index `Online` with a hole
    /// in it; restarting over the *original* snapshot would still lose every row written after the
    /// snapshot was taken, because the wipe destroyed those maintenance writes too.
    generation: u64,
    /// How many more times this build may fail to make final progress before it is **poisoned**
    /// (`rmp` task #733) — dropped un-promoted, leaving its index `Populating` and therefore never
    /// served. Decremented on a chunk that could not read a node, and on a promotion blocked by a
    /// degraded index set; refilled by any chunk that does make progress.
    ///
    /// It exists because Graphus assumes storage faults are **persistent** (checksum / torn page). A
    /// build that retries an unreadable chunk forever never advances its cursor, and
    /// `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()` — an infinite loop at
    /// 100% CPU, re-scanning the store on every iteration. A bounded budget keeps a *transient* fault
    /// self-healing while guaranteeing termination against a permanent one.
    stall: u8,
    /// The in-flight writers that made this build SKIP a node, accumulated across every chunk (`rmp`
    /// task #778). Non-empty at completion means the snapshot was not fully indexed, so the build parks
    /// instead of promoting — see the conflict gate in
    /// [`advance_fulltext_build`](TxnCoordinator::advance_fulltext_build).
    ///
    /// This is drained from [`IndexSet::ft_build_conflict_writers`] after each chunk and accumulated
    /// **here, on the build**, rather than being read off the shared index set at completion. The shared
    /// record does not survive an [`IndexSet::clear`], and `clear` is called by every `rebuild_index` —
    /// which an unrelated `CREATE INDEX` / `CREATE CONSTRAINT` can run at any point between this build's
    /// chunks. Reading it at completion would therefore let a build that skipped a node in an early chunk
    /// promote `Online` over that hole, because an interleaved DDL had wiped the evidence.
    conflict_writers: Vec<TxnId>,
}

/// One in-progress **non-blocking** spatial (point) index build (`rmp` task #98), the analogue of
/// [`PendingFulltextBuild`] for the grid spatial index. Indexes the `snapshot` nodes a bounded chunk
/// at a time, then promotes the spatial index on `(label_token, prop_key)` to [`IndexState::Online`].
/// The same candidate-set argument applies: writes after the snapshot are maintained by
/// [`RecordStoreGraph::reindex_node`] and deletes / stale points are dropped by the query-time
/// re-check, so the snapshot only needs to cover the rows that already existed at build start.
struct PendingSpatialBuild {
    /// The server-unique name of the spatial index being built.
    name: String,
    /// The label token the index covers (so the per-node indexer knows which point property to grid).
    label_token: u32,
    /// The property-key token the index covers (a single point property).
    prop_key: u32,
    /// The node-id list captured at build start.
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; complete once `cursor >= snapshot.len()`.
    cursor: usize,
    /// The [`IndexSet::wipe_generation`] this build is indexing into (`rmp` task #733). If a
    /// `fail_closed` wipes the index set mid-build, the epoch changes and the build **re-takes its
    /// snapshot from the store and restarts from cursor 0** instead of resuming over an emptied tree.
    /// Resuming would index only the tail of the snapshot and then promote the index `Online` with a hole
    /// in it; restarting over the *original* snapshot would still lose every row written after the
    /// snapshot was taken, because the wipe destroyed those maintenance writes too.
    generation: u64,
    /// How many more times this build may fail to make final progress before it is **poisoned**
    /// (`rmp` task #733) — dropped un-promoted, leaving its index `Populating` and therefore never
    /// served. Decremented on a chunk that could not read a node, and on a promotion blocked by a
    /// degraded index set; refilled by any chunk that does make progress.
    ///
    /// It exists because Graphus assumes storage faults are **persistent** (checksum / torn page). A
    /// build that retries an unreadable chunk forever never advances its cursor, and
    /// `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()` — an infinite loop at
    /// 100% CPU, re-scanning the store on every iteration. A bounded budget keeps a *transient* fault
    /// self-healing while guaranteeing termination against a permanent one.
    stall: u8,
}

/// The observable progress of one index build — in flight or **parked poisoned** (`rmp` task #573).
///
/// Every non-blocking build ([`PendingIndexBuild`], [`PendingFulltextBuild`], [`PendingSpatialBuild`])
/// already carries the two numbers that describe its progress exactly: a `cursor` into a `snapshot`
/// captured at build start. This is that pair, named and lifted to the public surface so the server can
/// render it (`SHOW INDEXES`' `populationPercent`) and meter it, without the listing having to know how a
/// build is represented.
///
/// # Why `poisoned` belongs here
///
/// A poisoned build (`rmp` task #733) is one a storage fault stopped for good: it is parked, un-promoted,
/// and its index stays `Populating` **forever** — never served, so answers remain correct via the scan,
/// but never accelerated either — until the store reads cleanly again and it is resurrected. Without this
/// flag a permanently-parked build is indistinguishable from a healthy build at 1%, which is precisely
/// the operability hole `rmp` #573 closes: an operator staring at a `Populating` index cannot tell a
/// normal ~14 s window from indefinite degradation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexBuildProgress {
    /// The name of the index this build populates — the same name `SHOW INDEXES` lists it under, so a
    /// listing row can be matched to its build.
    pub name: String,
    /// Entities indexed so far (the build cursor). Never exceeds [`total`](Self::total).
    pub done: usize,
    /// The length of the snapshot captured at build start — the denominator. Zero when the build had
    /// nothing to index (an empty store), in which case it promotes on its next tick.
    pub total: usize,
    /// Whether this build is **parked poisoned** (`rmp` task #733) rather than in flight: a storage fault
    /// stopped it, [`done`](Self::done) is frozen, and it makes no further progress until
    /// [`retry_poisoned_index_builds`](TxnCoordinator::retry_poisoned_index_builds) resurrects it.
    pub poisoned: bool,
}

/// The aggregate index-build numbers, with **no** per-build detail (`rmp` task #573) — the cheap
/// counterpart of [`IndexBuildProgress`], for the server's per-loop-iteration metrics publish.
///
/// [`TxnCoordinator::index_build_progress`] resolves a name per build, which allocates; the engine loop
/// evaluates its gauges on *every* iteration, so it must not pay that. This carries only what a gauge
/// needs, and computing it allocates nothing and touches no store (see
/// [`TxnCoordinator::index_build_totals`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexBuildTotals {
    /// Builds currently in flight.
    pub pending: usize,
    /// Builds that exist but are not progressing: parked **poisoned** by a storage fault (`rmp` task
    /// #733) *or* paused on an in-flight writer's uncommitted value (`rmp` task #778).
    ///
    /// Both are counted here because the gauge answers one operator question — "is an index declared but
    /// not being built?" — and leaving the #778 pause out made an index stuck `Populating` look like an
    /// idle, healthy engine (`pending == 0`, `parked == 0`). They differ in urgency: a poisoned build
    /// needs the store fixed, a paused one clears itself when the blocking transaction ends. A paused
    /// build is deliberately NOT counted by
    /// [`poisoned_index_builds`](TxnCoordinator::poisoned_index_builds), which drives the poison backoff
    /// and the `ERROR`-level operator log — a transient write conflict is not a fault and must not
    /// escalate like one.
    pub parked: usize,
    /// `Σ (snapshot.len() - cursor)` over the **in-flight** builds — entities still to index. Parked
    /// builds are excluded: their remainder is frozen and would otherwise read as work in progress.
    pub entities_remaining: usize,
}

/// The owned, `Send` pieces an off-thread reader needs to run a read-only statement against a
/// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph), captured on the engine thread by
/// [`TxnCoordinator::read_task_inputs`] (`rmp` task #336, Slice 3b-ii).
///
/// Every field is `Send` (compile-asserted just below), so the whole bundle moves cleanly
/// to a reader thread. It holds **no** `Rc`/`RefCell` and no live borrow of the store: the
/// [`StoreReadView`] is an `Arc`-shared page cache over an owned metadata snapshot, the
/// [`CommitRegistry`] is a clone, and the [`SsiReadBuffer`] is freshly minted for the reader.
pub struct ReadTaskInputs<D: BlockDevice, S: LogSink> {
    /// The owned decode surface over the committed store (`Arc<pool>` + `MetaSnapshot`).
    pub view: StoreReadView<D, S>,
    /// The owned `id ↔ name` token dictionary.
    pub tokens: TokenSnapshot,
    /// This reader's MVCC read snapshot (begin timestamp + owner txn).
    pub snapshot: Snapshot,
    /// A clone of the store's commit registry (resolves an in-flight writer to its outcome).
    pub registry: CommitRegistry,
    /// A fresh, empty SIREAD-marker buffer tagged with the reader's txn.
    pub buffer: SsiReadBuffer,
    /// A `Send + Sync` snapshot of the declared full-text index catalogue (`rmp` task #546), so an
    /// off-thread `CALL db.index.fulltext.queryNodes(name, …)` resolves the index by name and
    /// recomputes its matches from this reader's MVCC snapshot — without the coordinator's `!Send`
    /// [`IndexSet`](crate::index_set::IndexSet). Usually empty (no full-text index declared).
    pub fulltext: crate::read_source::FulltextReadSnapshot,
    /// A `Send + Sync` memo of the node-property **equality seek results** this plan will ask for
    /// (`rmp` task #755, Slice S2), pre-run on the engine thread against the live index so the reader
    /// serves a real seek instead of declining to a full scan. Empty (the default) unless the dispatch
    /// site fills it via [`TxnCoordinator::index_candidates_for`] — a miss simply declines, so an
    /// unfilled capture is always safe.
    pub index_candidates: crate::read_source::IndexCandidateCapture,
    /// A `Send + Sync` memo of the **count-store answers** this plan will ask for (`rmp` task #866),
    /// captured on the engine thread together with the verdict that they are equivalent to what this
    /// reader's snapshot would count. Empty (the default) unless the dispatch site fills it via
    /// [`TxnCoordinator::count_store_for`] — a miss simply declines to the scan, so an unfilled capture
    /// is always safe, and it is deliberately left empty whenever the equivalence predicate fails.
    pub count_store: crate::read_source::CountStoreCapture,
}

// `rmp` #336 Slice 3b-ii: `ReadTaskInputs` is captured on the engine thread and MOVED into the
// `ReadTask` sent to a reader thread, so it MUST be `Send`. A compile-time assertion (no runtime
// body) that fails to build the instant a non-`Send` field is introduced — making the off-thread
// dispatch's safety explicit here rather than only as a distant error at the `SyncSender<ReadTask>`
// send site. Every field is `Send`: `StoreReadView`/`TokenSnapshot` are `Send + Sync` (Slice 3a),
// `Snapshot` is `Copy`, and `CommitRegistry`/`SsiReadBuffer` are plain owned data. Asserted both for
// the concrete DST instantiation and generically over the `D, S: Send + Sync` bound the view requires.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_read_task_inputs() {
        assert_send::<ReadTaskInputs<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>>();
        fn assert_generic<D: BlockDevice + Send + Sync, S: LogSink + Send + Sync>() {
            fn inner<T: Send>() {}
            inner::<ReadTaskInputs<D, S>>();
        }
        assert_generic::<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>();
    }
    let _ = assert_read_task_inputs;
};

/// **The index-build queues, behind one latch** (`rmp` #1033, layer 7b of #975).
///
/// Eight collections that are one piece of state, because a build is *moved* between them: off
/// `pending` into `poisoned` when the store cannot be scanned, out of `poisoned` back into `pending`
/// once it reads cleanly, into `conflicted` when a concurrent writer wins the declaration. Each of
/// those is a move, so a reader that caught two collections at different instants would see one build
/// in both queues or in neither — and `has_pending_index_builds()`, which the engine polls to decide
/// whether it still has work to drive, would answer from a state that never existed.
///
/// One latch, because this is **index-build cadence**: a declaration enqueues, and the engine drains a
/// bounded slice per tick. Nothing here is on the row path.
// No `Debug`: the build structs carry index snapshots, and a derived `Debug` on those would render
// whole trees. `Default` only.
#[derive(Default)]
struct IndexBuilds {
    /// Queue of in-progress **non-blocking** index builds (`rmp` task #91), advanced in bounded
    /// chunks by [`advance_index_builds`](TxnCoordinator::advance_index_builds) between engine commands. The
    /// front build is the one currently being populated; each completes (durably promoted to
    /// [`IndexState::Online`]) before the next starts, so the queue is processed in declaration order.
    pending_builds: VecDeque<PendingIndexBuild>,
    /// Queue of in-progress **non-blocking** full-text index builds (`rmp` task #72), the analogue of
    /// [`pending_builds`](Self#structfield.pending_builds) for the inverted index, advanced by
    /// [`advance_index_builds`](TxnCoordinator::advance_index_builds) alongside the node-property builds.
    pending_fulltext_builds: VecDeque<PendingFulltextBuild>,
    /// Queue of in-progress **non-blocking** spatial (point) index builds (`rmp` task #98), the
    /// analogue of [`pending_fulltext_builds`](Self#structfield.pending_fulltext_builds) for the grid
    /// spatial index, advanced by [`advance_index_builds`](TxnCoordinator::advance_index_builds) alongside the
    /// other build kinds.
    pending_spatial_builds: VecDeque<PendingSpatialBuild>,
    /// Builds **poisoned** by a storage fault they could not get past (`rmp` task #733, M1): dropped from
    /// the pending queue un-promoted, so the engine terminates instead of spinning, but NOT thrown away.
    ///
    /// Poisoning used to be a one-way door: the index was left `Populating` (in memory *and* durably) with
    /// nothing in the process able to bring it back — `retry_degraded_index_rebuild` only runs while the
    /// set is degraded (which poisoning does not set), and the recovery promotion only runs in `new()`. So
    /// 32 unlucky chunks meant a dead index until someone restarted the server, with no log and no metric
    /// to say so. They are parked here instead and re-enqueued by
    /// [`retry_poisoned_index_builds`](TxnCoordinator::retry_poisoned_index_builds) once the store reads cleanly
    /// again.
    poisoned_builds: Vec<PendingIndexBuild>,
    /// Poisoned full-text builds — see [`poisoned_builds`](Self#structfield.poisoned_builds).
    poisoned_fulltext_builds: Vec<PendingFulltextBuild>,
    /// Poisoned spatial builds — see [`poisoned_builds`](Self#structfield.poisoned_builds).
    poisoned_spatial_builds: Vec<PendingSpatialBuild>,
    /// Full-text builds parked because an in-flight writer held the newest version of a covered property
    /// on a node they had to skip (`rmp` task #778) — each carrying, in its
    /// [`conflict_writers`](PendingFulltextBuild#structfield.conflict_writers), the transactions whose
    /// resolution unblocks it. Their index stays `Populating`, so every reader is on the
    /// snapshot-correct scan until then.
    ///
    /// Deliberately NOT [`poisoned_fulltext_builds`](Self#structfield.poisoned_fulltext_builds), for two
    /// reasons. It is not a *fault*: no storage read failed, nothing is broken, and it must not count
    /// toward [`poison_events`](Self#structfield.poison_events) (an operator alert for an index that
    /// silently stopped being built) or burn the poison backoff. And the graveyard's resurrection,
    /// `retry_poisoned_index_builds`, is driven on the threaded engine only by the idle tick — whose gate
    /// does not count parked builds (`rmp` #763) — so a build parked there while the engine is otherwise
    /// idle is never resurrected. This queue is drained by
    /// [`retry_conflicted_fulltext_builds`](TxnCoordinator::retry_conflicted_fulltext_builds), which
    /// [`advance_index_builds`](TxnCoordinator::advance_index_builds) — and therefore every command — drives.
    ///
    /// Excluded from [`has_pending_index_builds`](TxnCoordinator::has_pending_index_builds), exactly like the
    /// graveyard: `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()`, so a build
    /// waiting on a writer that stays open would otherwise spin the engine forever.
    conflicted_fulltext_builds: Vec<PendingFulltextBuild>,
    /// What every GC-driven index collection has done over this coordinator's life (`rmp` #992) —
    /// monotonic totals of [`DeadKeyCollection`], summed across passes.
    ///
    /// The pass report ([`GcPassReport::dead_index_keys`]) counts what the store **reported**, which
    /// is a different question from what the index layer **did** with it: a mechanism that reports
    /// thousands of dead keys and removes none of them looks identical, from the report alone, to one
    /// that has nothing to collect. `keys_retained` climbing while `entries_removed` stays flat is the
    /// signature of the re-check refusing everything, and `abandonments` is the concurrency gate in
    /// [`collect_dead_index_keys`](TxnCoordinator::collect_dead_index_keys) firing — nil today, and the first
    /// number to look at once the engine has more than one writer.
    index_collection_totals: IndexCollectionTotals,
}

#[cfg(debug_assertions)]
thread_local! {
    /// Whether this thread holds the index-build latch — see [`TxnCoordinator::builds`].
    static BUILDS_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The index-build latch's guard, which clears the re-entrancy tripwire on drop (`rmp` #1033).
struct BuildsGuard<'a> {
    inner: std::sync::MutexGuard<'a, IndexBuilds>,
}

impl std::ops::Deref for BuildsGuard<'_> {
    type Target = IndexBuilds;

    fn deref(&self) -> &IndexBuilds {
        &self.inner
    }
}

impl std::ops::DerefMut for BuildsGuard<'_> {
    fn deref_mut(&mut self) -> &mut IndexBuilds {
        &mut self.inner
    }
}

impl Drop for BuildsGuard<'_> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        BUILDS_HELD.with(|held| held.set(false));
    }
}

/// Drives concurrent, serializable Cypher transactions over one shared [`RecordStore`] (`04 §5`).
pub struct TxnCoordinator<D: BlockDevice, S: LogSink> {
    /// The one shared store, behind a [`SharedCell`] so each statement seam borrows it for the
    /// statement's duration while the transaction stays open across statements.
    ///
    /// All six shared fields below use the same wrapper. It was `Rc<RefCell<…>>` until `rmp` #1010,
    /// which is what kept this whole type `!Send`; [`SharedCell`] is `Arc<Mutex<…>>` with `RefCell`'s
    /// method names and — in a debug build — `RefCell`'s loud failure on re-entrancy, so the swap keeps
    /// a double borrow a panic instead of turning it into a silent deadlock. See
    /// [`crate::shared_cell`].
    store: SharedRef<RecordStore<D, S>>,
    /// The shared SSI dangerous-structure tracker (`04 §5.4`).
    ssi: SharedCell<SsiTracker>,
    /// The shared derived secondary [`IndexSet`] (`rmp` task #48): the always-present label index
    /// plus any declared node-property indexes. Rebuilt from the store on [`new`](Self::new) and on
    /// [`create_node_property_index`](Self::create_node_property_index), and maintained per write by
    /// each statement seam ([`RecordStoreGraph::reindex_node`]). It holds **candidate** ids only
    /// (never visibility-filtered), so it is in-memory and never committed or recovered — a fresh
    /// coordinator over a recovered store rebuilds a store-consistent index by construction.
    index: SharedCell<IndexSet>,
    /// The shared derived **columnar value cache** (`rmp` tasks #329 / #330): a contiguous,
    /// graphus-columnar-encoded snapshot of each declared `(label, property)` column, used to
    /// accelerate an analytical property scan / aggregation. Like [`Self::index`] it is derived,
    /// in-memory and **never committed or recovered** — rebuilt from the store on [`new`](Self::new)
    /// and re-captured on [`rebuild_columns`](Self::rebuild_columns) (a declaration / schema change).
    /// Unlike the index it caches the *value* (not just a candidate id); correctness is guaranteed at
    /// READ time by [`RecordStoreGraph::columnar_label_property_scan`], which re-validates every cached
    /// value against the node's current MVCC header and falls back to the authoritative row read on
    /// any mismatch — so the cache can be arbitrarily stale and never returns a wrong row. Maintenance
    /// is therefore **rebuild-only** (no commit-path hook), exactly the safe design `rmp` #329 mandates.
    columns: SharedCell<crate::column_cache::ColumnCache>,
    /// The derived per-`(label, property)` **zone-map data-skipping sidecar** (`rmp` task #331),
    /// opt-in via [`declare_zone_map`](Self::declare_zone_map), rebuilt from the store and maintained
    /// (widening) on write. In-memory, never persisted/recovered — a re-opened coordinator re-declares.
    zones: SharedCell<crate::zone_map::ZoneMap>,
    /// The **opt-in** type-bucketed CSR adjacency accelerator (`rmp` task #324, "Win 2"). `None` unless
    /// the [`csr_adjacency_enabled`](crate::read_source::csr_adjacency_enabled) knob is on at
    /// [`new`](Self::new) — so when off there is **zero** extra RAM and a typed `expand` behaves exactly
    /// as Win-1-only. When `Some`, it is built from the store on open (like [`Self::index`]) and handed
    /// to each statement seam; it is **marked stale** on the first relationship mutation and consulted
    /// only while fresh, falling back to the chain walk otherwise. Derived, in-memory, never recovered.
    csr: Option<SharedCell<crate::csr_adjacency::CsrAdjacency>>,
    /// Open transactions (begun, not yet committed/rolled back).
    active: std::sync::Mutex<HashMap<TxnId, ActiveTxn>>,
    /// Monotonic transaction-id source (distinct from the commit timestamp, which the store issues).
    next_txn_id: AtomicU64,
    /// **Every pending / poisoned / conflicted index build, behind one latch** (`rmp` #1033).
    /// See [`IndexBuilds`] for why the eight collections share it.
    builds: std::sync::Mutex<IndexBuilds>,
    /// Ticks still to skip before the next degraded-index rebuild attempt (`rmp` task #733), and the
    /// current backoff width. A `fail_closed` is usually transient, so the engine retries the rebuild
    /// from its tick ([`retry_degraded_index_rebuild`](TxnCoordinator::retry_degraded_index_rebuild))
    /// rather than staying scan-only until restart — but a rebuild is O(store), so a *persistent* fault
    /// must not re-scan every tick. The backoff doubles (1, 2, 4, … 1024) on each failed attempt and
    /// resets on success.
    degraded_retry_skip: AtomicU32,
    /// The current retry backoff width, in ticks — see
    /// [`degraded_retry_skip`](Self#structfield.degraded_retry_skip).
    degraded_retry_backoff: AtomicU32,
    /// Drains still to skip before the next `rmp` #778 conflict-repair attempt, and its current width —
    /// the exact throttle discipline [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild)
    /// applies, for a sharper version of the same reason.
    ///
    /// The repair is an O(store) `rebuild_index` on the engine thread, driven from the **command** path.
    /// A #778 conflict is inherently *flapping*: with overlapping write transactions touching a covered
    /// property, W1 resolves → full rebuild → the rebuild immediately conflicts with the already-open
    /// W2 → W2 resolves → full rebuild → … Unthrottled that is one whole-store scan per writer
    /// generation, sustained, on a database whose mandate is extreme write concurrency — and it thrashes
    /// every full-text index between `Online` and `Populating` while doing it. Backing off costs only
    /// latency on an index that is correct-but-unaccelerated meanwhile.
    conflict_retry_skip: AtomicU32,
    /// The current backoff width for [`conflict_retry_skip`](Self#structfield.conflict_retry_skip).
    conflict_retry_backoff: AtomicU32,
    /// Drains still to skip before the next POISON-only full-text/spatial repair (`rmp` task #803) —
    /// see [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild). Kept separate from
    /// [`degraded_retry_skip`](Self#structfield.degraded_retry_skip) because the two throttle opposite
    /// failure modes: a degraded set is a storage fault whose repair keeps FAILING, while a poison
    /// repair always succeeds and the hazard is it being re-triggered.
    ft_poison_repair_skip: AtomicU32,
    /// The current backoff width for
    /// [`ft_poison_repair_skip`](Self#structfield.ft_poison_repair_skip). Doubles on each successful
    /// poison-only repair and halves on every call that finds the engine healthy.
    ft_poison_repair_backoff: AtomicU32,
    /// How many POISON-driven full-store rebuilds this coordinator has actually run (`rmp` task #803)
    /// — monotonic. The repair is an O(store) rebuild of every index, so its RATE is the thing that
    /// must stay proportionate to the fault rather than to the traffic; a counter is the only way to
    /// hold that in a regression test.
    ft_poison_repairs: AtomicU64,
    /// Drains still to skip before the next VECTOR conflict re-fill attempt (`rmp` task #780) — the
    /// vector twin of [`conflict_retry_skip`](Self#structfield.conflict_retry_skip), kept SEPARATE so a
    /// flapping full-text conflict cannot starve a vector re-fill (or the reverse): while an index is
    /// blocked its every read pays an O(entities x dim) exact scan, so its repair must not queue behind
    /// an unrelated kind's backoff.
    vector_conflict_retry_skip: AtomicU32,
    /// The current backoff width for
    /// [`vector_conflict_retry_skip`](Self#structfield.vector_conflict_retry_skip).
    vector_conflict_retry_backoff: AtomicU32,
    /// How many builds have been poisoned over this coordinator's life (`rmp` task #733, M1) — monotonic.
    /// The server samples it to log at `ERROR` and drive a metric: an index that quietly stopped being
    /// built is exactly the kind of degradation that otherwise passes for "healthy but slow".
    poison_events: AtomicU64,
    /// Drains still to skip before the next poisoned-build resurrection probe (`rmp` task #733) — the
    /// throttle that stops a permanently-broken store from making the engine re-scan every command. Its
    /// width comes from [`poison_backoff`] applied to
    /// [`poison_resurrect_attempts`](Self#structfield.poison_resurrect_attempts).
    poison_retry_skip: AtomicU32,
    /// How many times in a row a parked build has been **resurrected without completing** (`rmp` task
    /// #733, B2 — the fix for a defect the M1 resurrection introduced).
    ///
    /// A resurrection re-snapshots with `scan_node_ids` and re-enqueues every parked build. But that
    /// probe only reads the node *slot* pages — not the property / label pages a build actually indexes.
    /// A build poisoned by an unreadable **property** page therefore passes the probe, is resurrected,
    /// re-drains, hits the same page, and re-poisons — every tick, forever, at ~100% CPU (the very spin
    /// the stall budget was meant to end, re-introduced through the resurrection door). This counts the
    /// consecutive failed resurrections so the backoff can grow geometrically (`2^attempts`, capped),
    /// collapsing the retry *rate* toward zero; it resets to `0` the moment the graveyard clears (a
    /// resurrected build actually completed), so a genuinely-healed store returns to fast retries.
    poison_resurrect_attempts: AtomicU32,
}

/// The deterministic, stable **auto-name** for a node-property index on `(label, property)`
/// (`rmp` task #624).
///
/// Used both when a `CREATE INDEX` omits a name and when backfilling a legacy anonymous index on open.
/// Form: `index_<label>_<property>`, with each part sanitized to the identifier charset `[A-Za-z0-9_]`
/// (any other character → `_`). This is a **pure** function of its arguments, so the same
/// `(label, property)` always yields the same base name across restarts and rebuilds — which is what
/// makes a legacy index's backfilled name stable.
///
/// The base can collide — two distinct `(label, property)` pairs can sanitize to the same string, or
/// the base can equal an explicitly-declared name. [`TxnCoordinator`] resolves such a collision by
/// appending the deterministic token suffix `_<label_token>_<property_token>` (see
/// `unique_auto_index_name`); because the resolved name is then persisted durably, the resolution is
/// computed at most once and is stable thereafter.
#[must_use]
pub fn auto_index_name(label: &str, property: &str) -> String {
    format!(
        "index_{}_{}",
        sanitize_identifier(label),
        sanitize_identifier(property)
    )
}

/// The token namespace a constraint's covering name lives in (`rmp` #638): a node label for the
/// node kinds, a relationship type for the relationship kinds. Used by the `IF NOT EXISTS`
/// equivalence check to resolve the covering token in the right namespace.
fn constraint_covering_namespace(kind: ConstraintKind) -> Namespace {
    if kind.is_relationship() {
        Namespace::RelType
    } else {
        Namespace::Label
    }
}

/// Maps every character outside the identifier charset `[A-Za-z0-9_]` to `_`, so an auto-generated
/// index name is always a clean bare identifier (`rmp` task #624).
fn sanitize_identifier(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Which schema catalog a name is being declared into, for the global name-uniqueness check
/// (`rmp` task #624). Names are unique across **all** catalogs; a `CREATE` rejects a name already used
/// by a *different* catalog while preserving each catalog's own re-declare (replace) semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameCatalog {
    /// The node-property index name catalog.
    NodeProperty,
    /// The relationship-property index name catalog (`rmp` task #646).
    RelProperty,
    /// The full-text index catalog.
    Fulltext,
    /// The spatial (point) index catalog.
    Spatial,
    /// The constraint catalog.
    Constraint,
    /// The composite (multi-property) node index catalog (`rmp` task #657).
    Composite,
    /// The composite (multi-property) relationship index catalog (`rmp` task #666).
    RelComposite,
    /// The text (trigram) node index catalog (`rmp` task #662).
    Text,
    /// The vector (HNSW) index catalog (`rmp` task #669).
    Vector,
}

/// A deterministic auto-name for the composite (multi-property) node index on `(label, properties)`
/// (`rmp` task #657) — the composite analogue of [`auto_index_name`]. Reuses the `index_` prefix and
/// appends each covered property in declared order (`index_<label>_<a>_<b>`), so the name is stable and
/// the covered tuple order is reflected in the name.
#[must_use]
pub fn auto_composite_index_name(label: &str, properties: &[String]) -> String {
    let mut name = format!("index_{}", sanitize_identifier(label));
    for property in properties {
        name.push('_');
        name.push_str(&sanitize_identifier(property));
    }
    name
}

/// A deterministic auto-name for the relationship-property index on `(rel_type, property)`
/// (`rmp` task #646) — the relationship analogue of [`auto_index_name`]. A distinct `rel_index_`
/// prefix keeps a rel index's auto-name from ever colliding with a node index's auto-name over the
/// same identifiers (they live in the one global name namespace).
#[must_use]
pub fn auto_rel_index_name(rel_type: &str, property: &str) -> String {
    format!(
        "rel_index_{}_{}",
        sanitize_identifier(rel_type),
        sanitize_identifier(property)
    )
}

/// A deterministic auto-name for the composite (multi-property) relationship index on
/// `(rel_type, properties)` (`rmp` task #666) — the relationship analogue of
/// [`auto_composite_index_name`]. The distinct `rel_index_` prefix keeps it from ever colliding with a
/// node composite's auto-name over the same identifiers; each covered property is appended in declared
/// order (`rel_index_<type>_<a>_<b>`), so the name is stable and reflects the covered tuple order.
#[must_use]
pub fn auto_rel_composite_index_name(rel_type: &str, properties: &[String]) -> String {
    let mut name = format!("rel_index_{}", sanitize_identifier(rel_type));
    for property in properties {
        name.push('_');
        name.push_str(&sanitize_identifier(property));
    }
    name
}

/// A deterministic auto-name for the **node** vector (HNSW) index on `(label, property)`
/// (`rmp` task #669). A distinct `vector_index_` prefix keeps it from ever colliding with any other
/// index kind's auto-name over the same identifiers (they share the one global name namespace).
#[must_use]
pub fn auto_vector_index_name(label: &str, property: &str) -> String {
    format!(
        "vector_index_{}_{}",
        sanitize_identifier(label),
        sanitize_identifier(property)
    )
}

/// A deterministic auto-name for the **relationship** vector (HNSW) index on `(rel_type, property)`
/// (`rmp` task #669) — the relationship analogue of [`auto_vector_index_name`]. The distinct
/// `vector_rel_index_` prefix keeps it from ever colliding with a node vector index's auto-name over
/// the same identifiers.
#[must_use]
pub fn auto_vector_rel_index_name(rel_type: &str, property: &str) -> String {
    format!(
        "vector_rel_index_{}_{}",
        sanitize_identifier(rel_type),
        sanitize_identifier(property)
    )
}

/// Maps a durable [`VectorSimilarity`] discriminant to the in-memory `graphus_index::Similarity`
/// (`rmp` task #669). Storage does not depend on `graphus-index`, so the metric is stored as its own
/// byte enum and translated here when the query layer (re)builds the HNSW graph.
#[must_use]
pub(crate) fn similarity_from_storage(similarity: VectorSimilarity) -> Similarity {
    match similarity {
        VectorSimilarity::Cosine => Similarity::Cosine,
        VectorSimilarity::Euclidean => Similarity::Euclidean,
    }
}

/// A test-only rendezvous between the two phases of `collect_dead_index_keys` (`rmp` #1022).
///
/// The fix is an ORDERING — the commit clock is read under the index's hold rather than while the
/// store is still held — and an ordering is not observable by racing two threads and hoping: a
/// free-running ticker advances the clock during the witness read as well, so the batch is abandoned
/// either way and the test passes under the defect. (That is exactly what the first draft of the test
/// below did, and it is why this hook exists rather than being avoided.) Pinning the advance to the
/// one interval that distinguishes the two orderings is the only way to make the ordering itself
/// falsifiable.
///
/// Compiled out entirely outside `cfg(test)`, so the shipped path has neither the branch nor the load.
#[cfg(test)]
pub(crate) static BETWEEN_WITNESS_AND_REMOVAL: std::sync::Mutex<
    Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
> = std::sync::Mutex::new(None);

/// Runs the `rmp` #1022 rendezvous, if a test installed one.
#[cfg(test)]
fn between_witness_and_removal() {
    let hook = BETWEEN_WITNESS_AND_REMOVAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(f) = hook {
        f();
    }
}

impl<D: BlockDevice, S: LogSink> TxnCoordinator<D, S> {
    /// A coordinator over `store` with no open transactions.
    ///
    /// The derived [`IndexSet`] is built empty and then **rebuilt** from `store` so it is consistent
    /// with the persisted graph by construction (`rmp` task #48). Over a freshly-recovered store this
    /// is precisely the crash-recovery requirement: a new coordinator's index reflects exactly the
    /// recovered, committed graph — nothing to commit or replay for the index itself.
    ///
    /// # Resuming an interrupted non-blocking build (the `rmp` task #91 crash path)
    ///
    /// A non-blocking index build ([`begin_online_node_property_index`](Self::begin_online_node_property_index))
    /// records its catalog entry durably as [`IndexState::Populating`] and only flips it to
    /// [`IndexState::Online`] once every snapshot node is indexed. If a crash interrupts a build, its
    /// catalog entry recovers `Populating`. But `rebuild_index` above has just **synchronously and
    /// fully** repopulated *every registered index* — `Populating` ones included — from the recovered
    /// store, so an interrupted build is now actually complete. We therefore **promote every
    /// durable-`Populating` index to `Online`** here, in one committed transaction, and mirror the
    /// promotion in the in-memory set. Startup is allowed to block: the server is not yet serving when
    /// the coordinator is constructed (see `graphus_server::engine::spawn_engine`). After this, no
    /// build is left pending — they either completed online before the crash or are completed by the
    /// rebuild here.
    #[must_use]
    pub fn new(store: RecordStore<D, S>) -> Self {
        // Seed the transaction-id counter **past** every id already in the durable WAL. Transaction
        // ids are written into the WAL but are not otherwise persisted, so a reopened coordinator that
        // restarted its counter from `0` would reuse ids from before the crash. A reused id is fatal to
        // ARIES recovery: a later crash's analysis collapses both incarnations into one
        // Active-Transaction-Table entry, and if the post-recovery incarnation committed, the pre-crash
        // *uncommitted* incarnation stops being classified as a loser — its redone effects are never
        // undone and an uncommitted record survives (an atomicity violation). Resuming past the
        // recovered high-water keeps ids globally unique across recovery. (`0` for a fresh store.)
        let recovered_txn_hw = store.recovered_txn_hw();
        let store = SharedRef::new(store);
        let index = SharedCell::new(IndexSet::new());
        Self::rebuild_index(&store, &index);
        // Promote any index left `Populating` by an interrupted `rmp` task #91 build: the rebuild
        // above already fully populated it from the recovered store, so it is complete. Minted from the
        // recovered id high-water so even the promotion transaction never reuses a pre-crash id.
        let next_txn_id =
            Self::promote_recovered_populating_indexes(&store, &index, recovered_txn_hw);
        // Backfill a deterministic, durable auto-name for every declared node-property index that has
        // none — a **legacy anonymous** index persisted before named indexes existed (`rmp` task #624).
        // After this, every declared index is named end-to-end (droppable by name, listed with a name in
        // `SHOW INDEXES`), and the name is stable across restarts because it is now durable.
        let next_txn_id = Self::backfill_recovered_index_names(&store, next_txn_id);
        // The opt-in CSR adjacency (`rmp` #324, Win 2): built from the store on open ONLY when the knob
        // is enabled, so the default (off) path allocates nothing. Like the index it is derived and
        // never recovered — a fresh coordinator over a recovered store rebuilds a store-consistent CSR.
        let csr = if crate::read_source::csr_adjacency_enabled() {
            let mut adjacency = crate::csr_adjacency::CsrAdjacency::empty();
            adjacency.build_from_store(store.borrow());
            Some(SharedCell::new(adjacency))
        } else {
            None
        };
        Self {
            store,
            ssi: SharedCell::new(SsiTracker::new()),
            index,
            // The columnar cache starts with no declared columns; a column is declared (and then
            // captured) via `declare_columnar_cache`. Derived/in-memory, never recovered (`rmp` #329),
            // so a fresh coordinator over a recovered store simply re-declares + re-captures as asked.
            columns: SharedCell::new(crate::column_cache::ColumnCache::new()),
            // The zone-map data-skipping sidecar (`rmp` #331) likewise starts empty; columns are
            // declared via `declare_zone_map` and rebuilt from the store, derived/never-recovered.
            zones: SharedCell::new(crate::zone_map::ZoneMap::new()),
            csr,
            active: std::sync::Mutex::new(HashMap::new()),
            next_txn_id: AtomicU64::new(next_txn_id),
            builds: std::sync::Mutex::new(IndexBuilds::default()),
            degraded_retry_skip: AtomicU32::new(0),
            degraded_retry_backoff: AtomicU32::new(1),
            conflict_retry_skip: AtomicU32::new(0),
            conflict_retry_backoff: AtomicU32::new(1),
            ft_poison_repair_skip: AtomicU32::new(0),
            ft_poison_repair_backoff: AtomicU32::new(1),
            ft_poison_repairs: AtomicU64::new(0),
            vector_conflict_retry_skip: AtomicU32::new(0),
            vector_conflict_retry_backoff: AtomicU32::new(1),
            poison_events: AtomicU64::new(0),
            poison_retry_skip: AtomicU32::new(0),
            poison_resurrect_attempts: AtomicU32::new(0),
        }
    }

    /// Recomputes the equi-depth selectivity histogram of the node-property index on
    /// `(label_token, prop_key)`, in its own committed transaction — so an index that has just come
    /// [`IndexState::Online`] is **born with real statistics** and the planner estimates ranges and
    /// joins over it from the actual data distribution instead of the
    /// [`DEFAULT_PREDICATE_SELECTIVITY`](crate::cardinality::DEFAULT_PREDICATE_SELECTIVITY) constant
    /// (`rmp` task #572). No operator action (`db.resampleIndex`) is needed for a fresh index.
    ///
    /// # Why this is a second pass, not a fold into the build scan
    ///
    /// The index build's scan ([`index_one_node`](Self::index_one_node)) reads through
    /// `RecordStore::node_labels` / `superset_scan_node_property_values` — **raw** store reads with
    /// no MVCC visibility filtering. That is sound for the *tree*, which is a **candidate** source:
    /// a seek
    /// re-checks every candidate against the reader's snapshot, so an extra invisible version costs a
    /// rejected candidate, never a wrong answer. A histogram has no such re-check — it is consumed
    /// **directly** as an estimate — so folding it into that scan would describe a graph that never
    /// existed at any snapshot (counting superseded and uncommitted property versions). The histogram
    /// must therefore be built over the visibility-filtered seam, which is a separate read.
    ///
    /// # Why the coordinator, and not the procedure
    ///
    /// This is the ONLY place a histogram recompute is executed. `db.resampleIndex` does not do the
    /// work itself: it runs inside the **caller's** transaction, and Neo4j's `db.resampleIndex`
    /// schedules a background job that ignores the caller's transaction entirely — so executing the
    /// resample outside it is the conformant behaviour, not a workaround. The procedure therefore only
    /// *queues* a request, and this method — a yield-free auto-commit transaction — executes it.
    ///
    /// Historical note: this split was originally introduced to *avoid triggering* `rmp` #734, under
    /// which a catalog mutation staged in a transaction the engine yields across survived its own
    /// rollback (the rollback restored the catalog's schema half wholesale whenever any other
    /// transaction was open). That gap is now **closed** — `RecordStore` tracks catalog DDL
    /// per-transaction and undoes exactly the rolling-back transaction's own — so the split here stands
    /// on its Neo4j-conformance merit alone, and no longer on a precondition another author must
    /// preserve.
    ///
    /// # Cost and failure policy
    ///
    /// One label scan per created index, on a DDL that already scans the store to populate the tree.
    /// It is **best-effort**: a failure leaves the index fully created and usable with *no* histogram,
    /// which is exactly the pre-`rmp`-#572 behaviour (the estimator falls back to its constant). A
    /// missing statistic makes a plan less well informed, never wrong — so it must never fail a valid
    /// DDL, and a faulted scan publishes nothing at all (`rmp` task #733 fail-closed, enforced inside
    /// [`RecordStoreGraph::recompute_property_histogram`]).
    ///
    /// The scan runs at **snapshot isolation** and so registers no SIREAD markers: seeding a statistic
    /// must never abort a concurrent user transaction (see the demotion note in the body).
    ///
    /// `D`/`S` carry `Send + Sync + 'static` for the same reason [`statement`](Self::statement) does —
    /// the statement seam this drives is bounded that way; every real store instantiation already
    /// meets these bounds.
    fn seed_index_histogram(&self, label_token: u32, prop_key: u32)
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        // Resolve the token names the recompute takes. A token with no resolvable name is a
        // defensively-skipped impossibility for a live, just-created index.
        let Some((label, property)) = ({
            let store = self.store.borrow();
            match (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) {
                (Some(l), Some(p)) => Some((l.to_owned(), p.to_owned())),
                _ => None,
            }
        }) else {
            return;
        };

        let txn = self.begin_serializable();
        // SNAPSHOT ISOLATION, deliberately (`rmp` #545's rule applied to an internal read). The scan
        // below would otherwise merge SIREAD markers for the whole label into the shared tracker,
        // handing every in-flight writer of that label an in-conflict it would not otherwise have — so
        // a `CREATE INDEX` could ABORT a concurrent user transaction that was going to commit, purely
        // to compute an estimate. That is the trade `rmp` #545 already rejected for ordinary reads
        // ("a read carries no serializability overhead and can never cause a writer to abort"), and it
        // applies with more force here: this read is internal and its only output is a *discardable*
        // statistic. Snapshot isolation reads the same consistent point-in-time graph — only the
        // conflict tracking is dropped — so the histogram is unchanged while concurrent writers are
        // left alone. The histogram write is not SSI-tracked either (it goes straight to the catalog,
        // never through `record_write`), so this transaction genuinely is a reader to SSI.
        self.demote_read_to_snapshot(txn);
        let recomputed = {
            let graph = match self.statement(txn) {
                Ok(g) => g,
                Err(_) => {
                    // Could not open a statement seam; leave the index without statistics.
                    let _ = self.rollback(txn);
                    return;
                }
            };
            // The INHERENT recompute, deliberately — not the `GraphAccess::request_index_resample`
            // seam, which only *queues* a request for this very drain and would loop back here forever.
            // This is the one place the work actually happens.
            graph
                .recompute_property_histogram(&label, &property)
                .is_ok()
        };
        if recomputed {
            {
                if self.commit(txn).is_err() {
                    // The histogram could not be made durable. The index itself is already committed
                    // and `Online`; the planner simply falls back until a `db.resampleIndex`.
                    //
                    // ROLL BACK EXPLICITLY. `commit` propagates the store error with `?` *before* it
                    // reaches `self.active.remove(&txn)`, so a swallowed failure would leave this
                    // transaction in `active` forever — and `oldest_active_snapshot` is a `min` over
                    // `active`, so it would permanently pin the MVCC GC watermark, the SSI prune
                    // (`rmp` #552) and the WAL reclaim floor. It is also unreapable: the `rmp` #477 age
                    // sweep only sees transactions opened via `begin_at`. `rollback` frees
                    // `active`/`ssi` through `abort`'s cleanup guard even if the undo fails.
                    let _ = self.rollback(txn);
                }
            }
        } else {
            // The scan faulted, so nothing was published (`rmp` task #733 fail-closed). Discard the
            // transaction and leave the index statistic-free rather than failing a DDL that otherwise
            // succeeded, or publishing a histogram built over a partial scan.
            let _ = self.rollback(txn);
        }
    }

    /// Promotes every durable-[`IndexState::Populating`] node-property index to
    /// [`IndexState::Online`] (catalog + in-memory set), in one committed transaction minted from
    /// `next_txn_id`. Returns the advanced `next_txn_id` (so [`new`](Self::new) keeps its monotonic
    /// id source consistent). A no-op (no commit) when no index is `Populating`.
    ///
    /// This is the crash-recovery completion of an interrupted non-blocking build (`rmp` task #91):
    /// by the time this runs the rebuild has already fully populated the in-memory index, so the
    /// durable state simply needs to catch up. The candidate-set contract makes this sound regardless:
    /// even if some node were missed, a seek re-checks the store, so promoting can only ever expose a
    /// fully-populated index. Errors interning/committing are swallowed best-effort: a failed promotion
    /// leaves the index `Populating` (withheld from the planner, scan-and-filter fallback stays
    /// correct), to be retried on the next open.
    fn promote_recovered_populating_indexes(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        next_txn_id: u64,
    ) -> u64 {
        // The whole premise of this promotion is the sentence above: *"the rebuild has already fully
        // populated it from the recovered store, so it is complete"*. When the open-time rebuild **failed
        // closed** that premise is false — the trees are empty or holed and every index was demoted — so
        // promoting anything now would publish `Online`, durably and in memory, an index with no rows in
        // it (`rmp` task #733).
        //
        // That is the whole `rmp` #733 defect, resurrected on the recovery path, and it is worse here:
        // the flip is DURABLE, so it also survives the restart that would otherwise have repaired it. The
        // planner would route a real `NodeIndexSeek` at the empty tree (committed rows invisible), and
        // `unique_conflict` — which trusts that tree as an EXACT candidate source — would let an
        // `IS UNIQUE` constraint accept a duplicate. It further defeated the `SHOW INDEXES` effective-
        // state machinery, which trusts the in-memory state this would have just falsified.
        //
        // Abort: leave every index `Populating` (withheld from the planner, and now honestly reported),
        // let the degraded rebuild retry repair the trees, and promote on a later open.
        if index.borrow().is_degraded() {
            return next_txn_id;
        }
        let populating: Vec<(u32, u32)> = store
            .borrow()
            .node_property_indexes()
            .into_iter()
            .filter(|(_, _, state)| *state == IndexState::Populating)
            .map(|(label_token, prop_key, _)| (label_token, prop_key))
            .collect();
        // Full-text indexes left `Populating` by an interrupted `rmp` task #72 build are promoted the
        // same way — the rebuild above has already fully repopulated their inverted index from the
        // recovered store, so the durable state just needs to catch up.
        let populating_fulltext: Vec<(String, FulltextIndexEntry)> = store
            .borrow()
            .fulltext_indexes()
            .into_iter()
            .filter(|(_, entry)| entry.state == IndexState::Populating)
            .collect();
        // Spatial indexes left `Populating` by an interrupted `rmp` task #98 build are promoted the
        // same way — the rebuild above has already fully repopulated their grid from the recovered
        // store, so the durable state just needs to catch up.
        let populating_spatial: Vec<(String, SpatialIndexEntry)> = store
            .borrow()
            .spatial_indexes()
            .into_iter()
            .filter(|(_, entry)| entry.state == IndexState::Populating)
            .collect();
        if populating.is_empty() && populating_fulltext.is_empty() && populating_spatial.is_empty()
        {
            return next_txn_id;
        }

        let txn = TxnId(next_txn_id + 1);
        store.borrow_mut().begin(txn);
        {
            let store = store.borrow_mut();
            for &(label_token, prop_key) in &populating {
                store.set_node_property_index(txn, label_token, prop_key, IndexState::Online);
            }
            for (name, entry) in &populating_fulltext {
                store.set_fulltext_index(
                    txn,
                    name.clone(),
                    FulltextIndexEntry {
                        state: IndexState::Online,
                        ..entry.clone()
                    },
                );
            }
            for (name, entry) in &populating_spatial {
                store.set_spatial_index(
                    txn,
                    name.clone(),
                    SpatialIndexEntry {
                        state: IndexState::Online,
                        ..entry.clone()
                    },
                );
            }
        }
        if store.borrow_mut().commit(txn).is_err() {
            // Could not make the promotion durable; leave the indexes `Populating` (still correct via
            // the scan fallback) and reconcile on the next open.
            return next_txn_id + 1;
        }
        let mut idx = index.borrow_mut();
        for (label_token, prop_key) in populating {
            idx.set_node_property_state(label_token, prop_key, IndexState::Online);
        }
        for (name, _) in populating_fulltext {
            idx.set_fulltext_state(&name, IndexState::Online);
        }
        for (_, entry) in populating_spatial {
            // Route by entity (`rmp` task #664): a relationship point index promotes in the rel-keyed
            // map. (Relationship point indexes are created synchronous-`Online`, so in practice they are
            // never left `Populating` — this stays correct if one ever were.)
            if entry.entity.is_relationship() {
                idx.set_spatial_rel_state(
                    entry.label_token,
                    entry.property_token,
                    IndexState::Online,
                );
            } else {
                idx.set_spatial_state(entry.label_token, entry.property_token, IndexState::Online);
            }
        }
        next_txn_id + 1
    }

    /// Backfills a deterministic, durable **auto-name** for every declared node-property index that has
    /// none — a **legacy anonymous** index persisted before named indexes existed (`rmp` task #624). One
    /// committed transaction minted from `next_txn_id`; returns the advanced `next_txn_id`. A no-op (no
    /// commit) when every declared index is already named — so after the first migration this is free.
    ///
    /// The name assigned to each index is [`unique_auto_index_name`](Self::unique_auto_index_name),
    /// which resolves a base-name collision by a deterministic token suffix. Because each assignment is
    /// applied to the store *before* the next index's name is computed, two legacy indexes whose bases
    /// collide are disambiguated deterministically (the ascending `(label_token, prop_key)` iteration
    /// order is stable). Once persisted here, every name is read back verbatim on the next open, so the
    /// migration is stable regardless.
    ///
    /// Errors interning/committing are swallowed best-effort: a failed backfill leaves the affected
    /// indexes nameless (reconciled on the next open), and [`list_node_property_indexes`]
    /// (Self::list_node_property_indexes) falls back to the freshly-computed auto-name meanwhile, so
    /// reads stay correct. Startup is allowed to block (the engine is not yet serving).
    fn backfill_recovered_index_names(
        store: &SharedRef<RecordStore<D, S>>,
        next_txn_id: u64,
    ) -> u64 {
        // Which declared node-property indexes carry no durable name? (Legacy anonymous indexes.)
        let nameless: Vec<(u32, u32)> = {
            let store = store.borrow();
            store
                .node_property_indexes()
                .into_iter()
                .filter(|(lt, pk, _)| store.node_property_index_name_for(*lt, *pk).is_none())
                .map(|(lt, pk, _)| (lt, pk))
                .collect()
        };
        if nameless.is_empty() {
            return next_txn_id;
        }

        let txn = TxnId(next_txn_id + 1);
        store.borrow_mut().begin(txn);
        {
            let store = store.borrow_mut();
            for (label_token, prop_key) in nameless {
                // Resolve the tokens to names; skip (leave nameless, retried next open) if a token has no
                // resolvable name — a defensive impossibility for a live token.
                let (Some(label), Some(property)) = (
                    store
                        .token_name(Namespace::Label, label_token)
                        .map(|n| n.to_string()),
                    store
                        .token_name(Namespace::PropKey, prop_key)
                        .map(|n| n.to_string()),
                ) else {
                    continue;
                };
                // Compute against the *current* store state (including names assigned earlier in this
                // same pass) so colliding bases are disambiguated deterministically.
                let name =
                    Self::unique_auto_index_name(store, &label, &property, label_token, prop_key);
                store.set_node_property_index_name(txn, name, label_token, prop_key);
            }
        }
        // The txn advanced an id whether or not the commit lands (mirrors the promote path). A failed
        // backfill commit is a best-effort no-op that self-heals: the auto-names stay in memory for
        // this session and are recomputed (identically, being a pure function of durable tokens) on
        // the next open, so a startup I/O error here never corrupts the catalog (`rmp` #624 audit,
        // LOW). Reads remain correct meanwhile; only DROP-by-auto-name would miss until the reopen.
        // Surface the durability event to stderr for observability rather than swallowing it silently
        // (startup only — the engine is not yet serving; the core crate carries no logging facade, so
        // this matches the top-level `graphus-server` fault convention).
        if let Err(e) = store.borrow_mut().commit(txn) {
            eprintln!(
                "graphus-cypher: WARN best-effort node-property index name backfill commit failed \
                 (auto-names stay in memory, recomputed on next open): {e}"
            );
        }
        next_txn_id + 1
    }

    /// Reloads the durable node-property index catalog into `index` (`rmp` task #90), then clears and
    /// repopulates `index` from every in-use node in `store` (`rmp` task #48): each node's label
    /// tokens go into the label index, and for each **registered** node-property index the node
    /// matches, its current property value is inserted.
    ///
    /// # Durable registration reload (the crash-recovery fix, `rmp` task #90)
    ///
    /// The set of declared node-property indexes is recovered from the store's durable index catalog
    /// **before** the rebuild scan, so a fresh coordinator over a recovered store re-registers exactly
    /// the indexes that were committed — no manual re-registration after recovery. A catalog entry
    /// recorded `Online` is registered `Online`; a `Populating` one is registered, populated by the
    /// scan below, and — since population is synchronous in this task — left registered (its promotion
    /// to `Online` is the coordinator's caller path; `rmp` task #91 owns the non-blocking flip). Any
    /// indexes already registered in `index` (e.g. one just declared via
    /// [`create_node_property_index`](Self::create_node_property_index)) are preserved: the reload only
    /// *adds* the durable set, and [`IndexSet::register_node_property_with_state`] is idempotent.
    ///
    /// This is the store-side analogue of [`RecordStoreGraph::reindex_node`], but it reads directly
    /// off the store (no MVCC snapshot). That is sound only because the trees it fills are **candidate**
    /// sets whose consumers re-check every hit against their own snapshot: an entry for a version some
    /// reader cannot see is a false POSITIVE the re-check filters out.
    ///
    /// # The governing asymmetry: a superset is safe, a subset is not
    ///
    /// A re-check can REMOVE a candidate; it can never RESURRECT one. So this refill must produce a
    /// candidate **SUPERSET** of what every reader could resolve. Anything less is unfixable downstream:
    /// a missing entry is a committed row silently lost to every seek, and for the trees backing NODE KEY
    /// / REL KEY it also makes the write path's duplicate check find nothing and ADMIT A COMMITTED
    /// DUPLICATE (`rmp` #683 / #765).
    ///
    /// The refill therefore indexes **every version in each chain**, not the newest one (`rmp` task
    /// #766). Newest-wins produced a subset and lost committed rows two ways, both reproduced and pinned
    /// by `tests/index_rebuild_uncommitted.rs`:
    ///
    /// - the newest version may be **UNCOMMITTED**, so the committed value was indexed nowhere and a
    ///   FRESH reader — the reader the `rmp` #765 watermark deliberately SERVES — sought it and got
    ///   nothing, permanently, even after that writer rolled back;
    /// - the versions an OLDER snapshot resolves were dropped, which is the `rmp` #765 defect.
    ///
    /// Reading the newest **committed** version instead was implemented and measured, and only moves the
    /// victim: the in-flight writer's own value would be missing, and `commit` does not re-insert index
    /// entries (they are made eagerly at write time and [`IndexSet::clear`] destroyed them), so that row
    /// stays lost once the writer commits. Only the every-version image serves both readers.
    ///
    /// The composite trees cannot simply index every version independently — a tuple must be internally
    /// consistent — so they index one tuple per observable **view**; see [`composite_candidate_tuples`].
    ///
    /// # Where the superset argument does NOT apply
    ///
    /// It holds only where the consumer re-checks the predicate. It does **not** hold for the full-text
    /// trees: [`RecordStoreGraph::fulltext_query`] re-checks a candidate's visibility and current label
    /// and nothing else, so a stale version's terms would be returned as a WRONG ROW rather than filtered.
    /// Those helpers stay newest-wins deliberately; their residual window is `rmp` #773. The
    /// single-value-per-entity trees (spatial's `node -> (cell, point)`, vector's one embedding per
    /// entity) cannot represent a superset at all.
    ///
    /// The rebuild still stamps [`IndexSet::note_trees_rebuilt`] with its high-water below, as a
    /// conservative `rmp` #765 safety net.
    ///
    /// Errors reading any single node/label/property are skipped (best-effort) and recorded as a rebuild
    /// gap, which fails the index closed (`rmp` #733) rather than leaving a hole a seek would read as
    /// "no such row". The store and the index are borrowed in separate, non-overlapping scopes.
    ///
    /// A fault on a **whole scan** (nodes or relationships) is different in kind: the rebuild cannot be
    /// completed, and since [`IndexSet::clear`] has already dropped every entry, the indexes would be
    /// left registered, `Online` and **empty** — silently answering every seek with zero rows. Such a
    /// fault therefore **fails closed** via [`IndexSet::fail_closed`], which makes every index unusable
    /// (not merely empty) so all consumers degrade to the always-correct store scan (`rmp` task #733).
    /// This matters at run time, not just on open: `rebuild_index` is also driven by index / constraint
    /// DDL.
    fn rebuild_index(store: &SharedRef<RecordStore<D, S>>, index: &SharedCell<IndexSet>) {
        // Recover the durable index catalog (`rmp` task #90) into the in-memory set first: this is
        // what makes registration survive a crash. Done before `clear` (which keeps the registered set
        // but wipes entries) so the rebuild scan below indexes the recovered indexes too.
        let durable: Vec<(u32, u32, IndexState)> = store.borrow().node_property_indexes();
        {
            let mut idx = index.borrow_mut();
            for (label_token, prop_key, state) in durable {
                idx.register_node_property_with_state(label_token, prop_key, state);
            }
        }

        // Recover the durable relationship-property index catalog (`rmp` task #646) the same way: a
        // fresh coordinator over a recovered store re-registers exactly the rel-property indexes that
        // were committed, so their backing trees are repopulated by the rel scan below.
        let durable_rel: Vec<(u32, u32, IndexState)> = store.borrow().rel_property_indexes();
        {
            let mut idx = index.borrow_mut();
            for (type_token, prop_key, state) in durable_rel {
                idx.register_rel_property_with_state(type_token, prop_key, state);
            }
        }

        // Recover the durable full-text index catalog (`rmp` task #72) the same way: register each
        // declared index in the in-memory set (analyzer + covered label/properties), so the rebuild
        // scan below populates its inverted index. An entry whose analyzer byte is unknown
        // (forward-incompatible) is skipped defensively — its inverted index stays empty and the
        // procedure surface returns no matches rather than mis-analyzing.
        let durable_fulltext: Vec<(String, FulltextIndexEntry)> = store.borrow().fulltext_indexes();
        {
            let mut idx = index.borrow_mut();
            for (name, entry) in durable_fulltext {
                let Some(analyzer) = Analyzer::from_byte(entry.analyzer) else {
                    continue;
                };
                // Route by entity (`rmp` task #663): a node index registers into the node full-text map
                // (covered by labels), a relationship index into the separate relationship full-text map
                // (covered by rel types). The rebuild scan below repopulates whichever inverted index
                // was registered here.
                if entry.entity.is_relationship() {
                    idx.register_fulltext_rel(
                        &name,
                        entry.tokens,
                        entry.property_tokens,
                        analyzer,
                        entry.state,
                    );
                } else {
                    idx.register_fulltext(
                        &name,
                        entry.tokens,
                        entry.property_tokens,
                        analyzer,
                        entry.state,
                    );
                }
            }
        }

        // Recover the durable spatial index catalog (`rmp` task #98) the same way: register each
        // declared index's grid in the in-memory set (covered label/property + state), so the rebuild
        // scan below repopulates the grid. A spatial index has no analyzer to validate; it is keyed by
        // `(label_token, prop_key)` in the `IndexSet` (the catalog's `name` is the durable identifier).
        let durable_spatial: Vec<(String, SpatialIndexEntry)> = store.borrow().spatial_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_spatial {
                // Route by entity (`rmp` task #664): a node point index registers into the node-keyed
                // spatial map (covered by labels), a relationship point index into the separate
                // relationship-keyed spatial map (covered by rel types). The rebuild scan below
                // repopulates whichever grid was registered here.
                if entry.entity.is_relationship() {
                    idx.register_spatial_rel(
                        entry.label_token,
                        entry.property_token,
                        graphus_index::DEFAULT_CELL_SIZE,
                        entry.state,
                    );
                } else {
                    idx.register_spatial(
                        entry.label_token,
                        entry.property_token,
                        graphus_index::DEFAULT_CELL_SIZE,
                        entry.state,
                    );
                }
            }
        }

        // Recover the durable constraint catalog (`rmp` tasks #99, #100) the same way: register each
        // declared constraint's rule (carrying its type descriptor) in the in-memory set, and register
        // the right backing index so the write-path duplicate check stays index-accelerated after a
        // crash:
        //   - UNIQUENESS  → a node-property index on its single `(label, property)` at `Online`;
        //   - NODE KEY    → a COMPOSITE index over its whole `(label, property tuple)`.
        // Existence and property-type need no backing index (pure per-node predicates). The rebuild
        // scan below repopulates whichever backing indexes were registered here.
        let durable_constraints: Vec<(String, ConstraintEntry)> = store.borrow().constraints();
        {
            let mut idx = index.borrow_mut();
            for (name, entry) in durable_constraints {
                idx.register_constraint(
                    &name,
                    entry.label_token,
                    entry.property_tokens.clone(),
                    entry.kind,
                    entry.type_descriptor.clone(),
                );
                match entry.kind {
                    ConstraintKind::Unique => {
                        if let [prop_key] = entry.property_tokens.as_slice() {
                            idx.register_node_property_with_state(
                                entry.label_token,
                                *prop_key,
                                IndexState::Online,
                            );
                        }
                    }
                    ConstraintKind::NodeKey => {
                        idx.register_composite(entry.label_token, entry.property_tokens.clone());
                    }
                    ConstraintKind::RelUnique => {
                        // A relationship uniqueness constraint (`rmp` #638) is backed by a
                        // relationship-property index on its single `(type, property)` (`rmp` task #646),
                        // so the write-time duplicate check is index-accelerated after a crash (the rel
                        // scan below repopulates it). The covering token is a relationship-**type** token.
                        if let [prop_key] = entry.property_tokens.as_slice() {
                            idx.register_rel_property_with_state(
                                entry.label_token,
                                *prop_key,
                                IndexState::Online,
                            );
                        }
                    }
                    // No backing index: pure per-entity predicates, plus RelKey / RelPropertyType which
                    // stay scan-based (a relationship COMPOSITE index is deferred; RelPropertyType is a
                    // pure per-relationship predicate).
                    ConstraintKind::Existence
                    | ConstraintKind::PropertyType
                    | ConstraintKind::RelExistence
                    | ConstraintKind::RelKey
                    | ConstraintKind::RelPropertyType => {}
                }
            }
        }

        // Register every durable **standalone composite index** (`rmp` task #657) in the in-memory set,
        // so the write path maintains it and the rebuild scan below repopulates its backing tree. This
        // is distinct from a node-key constraint's backing composite (registered above): a standalone
        // composite enforces no uniqueness. It is recorded `Online` in the durable catalog (a synchronous
        // build), so recovery repopulates a fully-online index, never a half-built one. The in-memory
        // composite map is keyed by `(label_token, property tuple)`, so a standalone composite and a
        // node key over the *same* tuple share one backing tree — always correct (both are pure
        // candidate sources re-checked against the store).
        let durable_composites: Vec<(String, CompositeIndexEntry)> =
            store.borrow().composite_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_composites {
                idx.register_composite(entry.label_token, entry.property_tokens);
            }
        }

        // Register every durable **standalone composite relationship index** (`rmp` task #666) in the
        // in-memory set, so the write path maintains it and the rebuild scan below repopulates its
        // backing tree — the relationship analogue of the node composite registration above. It is
        // recorded `Online` in the durable catalog (a synchronous build), so recovery repopulates a
        // fully-online index. Keyed by `(type_token, property tuple)` in the separate `rel_composite`
        // map (a numeric collision between a label token and a rel-type token never mixes the two).
        let durable_rel_composites: Vec<(String, RelCompositeIndexEntry)> =
            store.borrow().rel_composite_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_rel_composites {
                idx.register_rel_composite(entry.type_token, entry.property_tokens);
            }
        }

        // Register every durable **text (trigram) index** (`rmp` task #662) in the in-memory set, so the
        // write path maintains it and the rebuild scan below repopulates its trigram index. It is
        // recorded `Online` in the durable catalog (a synchronous build), so recovery repopulates a
        // fully-online index, never a half-built one. Keyed by `(label_token, prop_key)`, like spatial.
        let durable_text: Vec<(String, TextIndexEntry)> = store.borrow().text_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_text {
                idx.register_text(entry.label_token, entry.property_token, IndexState::Online);
            }
        }

        // Register every durable **vector (HNSW) index** (`rmp` task #669) in the in-memory set BEFORE
        // the rebuild scan below, so the write path maintains it and the scan repopulates its ANN graph.
        // It is recorded `Online` in the durable catalog (a synchronous build), so recovery repopulates a
        // fully-online index. Route by entity: a node index into the node-keyed `vector` map (covered by
        // labels), a relationship index into the separate rel-keyed `vector_rel` map (covered by rel
        // types). The declared dimension / similarity / m / ef_construction come straight from the durable
        // entry, so the rebuilt graph has exactly the shape the create recorded.
        let durable_vector: Vec<(String, VectorIndexEntry)> = store.borrow().vector_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_vector {
                let similarity = similarity_from_storage(entry.similarity);
                if entry.entity.is_relationship() {
                    idx.register_vector_rel(
                        entry.token,
                        entry.property_token,
                        entry.dimensions as usize,
                        similarity,
                        entry.m as usize,
                        entry.ef_construction as usize,
                        entry.state,
                    );
                } else {
                    idx.register_vector(
                        entry.token,
                        entry.property_token,
                        entry.dimensions as usize,
                        similarity,
                        entry.m as usize,
                        entry.ef_construction as usize,
                        entry.state,
                    );
                }
            }
        }

        index.borrow_mut().clear();
        // Re-register every bitmap column this session declared (`rmp` task #733, M2). A bitmap is opt-in
        // and has NO durable catalog entry, so unlike every other kind it cannot be recovered from the
        // store — a fail-closed retires the live index and only this brings it back. The scan below then
        // repopulates it (it is in `registered_bitmap()` again).
        index.borrow_mut().reregister_declared_bitmaps();

        // The set of registered node-property indexes (any state), captured before walking the store so
        // the index is not borrowed across a store borrow. A `Populating` index is maintained too (so
        // its entries are ready the instant it is promoted), so the rebuild reads the full set here;
        // the planner only ever sees the `Online` subset via `catalog()`.
        let registered: Vec<(u32, u32)> = index.borrow().registered_node_properties();

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A store-read fault on the whole scan means the rebuild CANNOT be completed. `clear()`
            // above already dropped every index's entries, so at this point every index is registered,
            // still `Online` — and EMPTY. That is the most dangerous state the engine can be in
            // (`rmp` task #733): the planner keeps routing seeks to those indexes, the write path keeps
            // consulting them for uniqueness / node-key duplicate detection, and the full-text /
            // vector procedures keep reading their postings — all returning ZERO rows, silently. (This
            // is not a recovery-only path: `rebuild_index` also runs at run time from five DDL
            // call sites, so a transient I/O fault during a `CREATE INDEX` could wipe the process's
            // in-memory indexes and serve wrong answers until restart.)
            //
            // So fail **closed**: make every index unusable rather than empty. `fail_closed` demotes
            // the state-carrying kinds out of `Online` (withdrawing them from the planner's catalog and
            // from every read seam, which since `rmp` #733 declines unless `Online`), unregisters the
            // state-less candidate sources (composite / bitmap), and poisons the full-text/spatial
            // freshness marker. Every consumer then degrades to the always-correct store scan — the
            // outcome the old comment here CLAIMED but did not deliver. The durable catalog is
            // untouched, so the schema survives and the next successful rebuild (any index/constraint
            // DDL, or reopening the store) restores the fast paths.
            Err(_) => {
                index.borrow_mut().fail_closed();
                return;
            }
        };

        let has_fulltext = !index.borrow().registered_fulltext().is_empty();
        // The registered spatial index keys `(label_token, prop_key)`, captured before the scan so the
        // index is not borrowed across a store borrow (`rmp` task #98).
        let registered_spatial: Vec<(u32, u32)> = index.borrow().registered_spatial();
        // The registered text (trigram) index keys `(label_token, prop_key)` (`rmp` task #662), captured
        // before the scan so the index is not borrowed across a store borrow.
        let registered_text: Vec<(u32, u32)> = index.borrow().registered_text();
        // The registered node vector index keys `(label_token, prop_key)` (`rmp` task #669), captured
        // before the scan so the index is not borrowed across a store borrow.
        let registered_vector: Vec<(u32, u32)> = index.borrow().registered_vector();
        // The registered composite index keys `(label_token, property tuple)` — a node-key constraint's
        // backing index (`rmp` task #100). Captured before the scan so the index is not borrowed across
        // a store borrow.
        let registered_composite: Vec<(u32, Vec<u32>)> = index.borrow().registered_composite();
        // The registered bitmap (low-cardinality) index keys (`rmp` task #328), captured before the
        // scan like the others. The bitmap is membership-exact, so the rebuild re-captures it whole.
        let registered_bitmap: Vec<(u32, u32)> = index.borrow().registered_bitmap();
        for id in node_ids {
            Self::index_one_node(store, index, id, &registered);
            // Repopulate the full-text inverted indexes from the same scan (`rmp` task #72), so a
            // recovered store rebuilds them store-consistently — only when at least one is declared.
            if has_fulltext {
                Self::index_one_node_fulltext(store, index, id);
            }
            // Repopulate the spatial grids from the same scan (`rmp` task #98), only when at least one
            // is declared.
            if !registered_spatial.is_empty() {
                Self::index_one_node_spatial(store, index, id, &registered_spatial);
            }
            // Repopulate the text (trigram) indexes from the same scan (`rmp` task #662), only when at
            // least one is declared.
            if !registered_text.is_empty() {
                Self::index_one_node_text(store, index, id, &registered_text);
            }
            // Repopulate the vector (HNSW) indexes from the same scan (`rmp` task #669), only when at
            // least one is declared.
            if !registered_vector.is_empty() {
                Self::index_one_node_vector(store, index, id, &registered_vector);
            }
            // Repopulate the composite indexes from the same scan (`rmp` task #100), only when at least
            // one node-key constraint is declared.
            if !registered_composite.is_empty() {
                Self::index_one_node_composite(store, index, id, &registered_composite);
            }
            // Repopulate the bitmap indexes from the same scan (`rmp` task #328), only when at least
            // one low-cardinality column is declared.
            if !registered_bitmap.is_empty() {
                Self::index_one_node_bitmap(store, index, id, &registered_bitmap);
            }
        }

        // Repopulate the relationship-property indexes (`rmp` task #646) and the relationship full-text
        // indexes (`rmp` task #663) from a relationship scan — but only when at least one of either is
        // declared, so a store with no relationship index pays nothing for the extra walk. Captured
        // before the scan so the index is not borrowed across a store borrow.
        let registered_rel: Vec<(u32, u32)> = index.borrow().registered_rel_properties();
        let has_rel_fulltext = index.borrow().has_any_fulltext_rel();
        // The registered relationship spatial index keys `(type_token, prop_key)` (`rmp` task #664),
        // captured before the scan so the index is not borrowed across a store borrow.
        let registered_rel_spatial: Vec<(u32, u32)> = index.borrow().registered_spatial_rel();
        // The registered composite relationship index keys `(type_token, property tuple)` (`rmp` task
        // #666), captured before the scan like the others.
        let registered_rel_composite: Vec<(u32, Vec<u32>)> =
            index.borrow().registered_rel_composite();
        // The registered relationship vector index keys `(type_token, prop_key)` (`rmp` task #669),
        // captured before the scan like the others.
        let registered_rel_vector: Vec<(u32, u32)> = index.borrow().registered_vector_rel();
        // A store-read fault enumerating the relationships **fails closed**, exactly like the node scan
        // above (`rmp` task #733): the relationship indexes would otherwise be left registered,
        // `Online` and EMPTY, silently answering every relationship seek / relationship full-text query
        // with zero rows. `fail_closed` is deliberately **total** (it demotes the node indexes too, not
        // just the relationship ones): a whole-scan storage fault means the store itself is faulting, so
        // preserving the node fast paths would only buy speed in a database that is already broken —
        // and a second, partial fail-closed mode is more surface to get wrong. Per-relationship read
        // faults inside `index_one_rel*` still skip that relationship best-effort (a missing candidate
        // in a *populated* index degrades that reader to a re-check, never to a wrong row).
        let needs_rel_scan = !registered_rel.is_empty()
            || has_rel_fulltext
            || !registered_rel_spatial.is_empty()
            || !registered_rel_composite.is_empty()
            || !registered_rel_vector.is_empty();
        if needs_rel_scan {
            let rel_ids = match store.borrow().scan_rel_ids() {
                Ok(ids) => ids,
                Err(_) => {
                    index.borrow_mut().fail_closed();
                    return;
                }
            };
            for id in rel_ids {
                if !registered_rel.is_empty() {
                    Self::index_one_rel(store, index, id, &registered_rel);
                }
                // Repopulate the relationship full-text inverted indexes (`rmp` task #663), only when at
                // least one is declared.
                if has_rel_fulltext {
                    Self::index_one_rel_fulltext(store, index, id);
                }
                // Repopulate the relationship spatial grids (`rmp` task #664), only when at least one is
                // declared.
                if !registered_rel_spatial.is_empty() {
                    Self::index_one_rel_spatial(store, index, id, &registered_rel_spatial);
                }
                // Repopulate the composite relationship indexes (`rmp` task #666), only when at least one
                // is declared.
                if !registered_rel_composite.is_empty() {
                    Self::index_one_rel_composite(store, index, id, &registered_rel_composite);
                }
                // Repopulate the relationship vector (HNSW) indexes (`rmp` task #669), only when at least
                // one is declared.
                if !registered_rel_vector.is_empty() {
                    Self::index_one_rel_vector(store, index, id, &registered_rel_vector);
                }
            }
        }

        // Did the rebuild have to SKIP an entity it could not read (`rmp` task #733)? The per-entity
        // helpers are best-effort, but "best effort" is not good enough while an index is being built:
        // an entity they skipped is absent from the label index (invisible to every `MATCH (n:Label)`)
        // and from every property index (invisible to every seek), and no re-check can resurrect it —
        // a committed row silently lost to queries for the life of the process. An index we know to be
        // an incomplete image of the store must not be published, so fail closed exactly as a failed
        // whole-scan does. (Empirically caught by the fault-injection sweep in
        // `tests/index_fail_closed.rs`: a single transient read fault inside the loop above used to
        // drop one node from the label index, and a plain `MATCH (a:Article)` then returned 299 of 300
        // rows — silently.)
        if index.borrow().rebuild_gap() {
            index.borrow_mut().fail_closed();
            return;
        }

        // Did the rebuild have to SKIP a full-text entity because an in-flight writer holds the newest
        // version of a covered property (`rmp` task #778)? Unlike the read fault above this is not a
        // fault and must not `fail_closed` the whole set — it is a transient write conflict, and every
        // OTHER index kind refilled above is unaffected (they hold every version, so a re-check drops the
        // extras). Only the single-value-per-entity full-text trees are holed, and only they are demoted:
        // `Populating` routes `fulltext_query` / `fulltext_query_rel` to the snapshot-correct scan, which
        // returns the committed row and not the writer's dirty term.
        //
        // The demotion is IN MEMORY only, so the durable catalog still says what it said. That is what
        // makes the repair automatic: the resurrection re-runs THIS function, whose re-registration pass
        // restores each index's state from that catalog and then refills it — so an index can only return
        // to `Online` by being rebuilt with no conflict. The conflict record itself is deliberately NOT
        // cleared here; `advance_index_builds` reads it to know which writers to wait on.
        if index.borrow().ft_build_conflict() {
            index.borrow_mut().demote_fulltext_for_conflict();
        }

        // Reset the cross-snapshot full-text/spatial freshness marker (`rmp` task #467). The rebuild
        // above re-inserted every full-text/spatial posting via the instrumented mutation methods,
        // which raised the transient dirty flag (and, on the recovery/DDL paths, may have to clear a
        // prior poison); the rebuilt index now reflects exactly the committed store state at the
        // current high-water. Stamp the marker to that high-water so a reader at-or-after it trusts the
        // index (index == committed state) and an older reader conservatively declines to the scan
        // path — and discard the build's dirty flag so it does not leak into the next user statement.
        let high_water = store.borrow().snapshot_ts();
        index.borrow_mut().reset_ft_spatial_marker(high_water);
        // The append-only class's twin of the marker above (`rmp` tasks #755 / #765). `clear()` above
        // wiped all four stale-retaining trees (`node_props`, `rel_props`, `composite`, `rel_composite`)
        // and the refill is NEWEST-WINS, so the stale entries an older snapshot still depends on were
        // destroyed, while the indexes stay `Online` and `heal()` clears `degraded`. Stamp the same
        // high-water so a seek serves only a reader at-or-after it; an older reader declines to the exact
        // scan. BOTH seams honour it: the captured off-thread seek
        // ([`IndexSet::capture_node_property_eq`]) and every inline seek
        // (`RecordStoreGraph::rebuilt_trees_serve_reader`).
        //
        // Every early return above is preceded by `fail_closed()` (degraded + all states `Populating`),
        // which the capture's gates 1/2 already refuse — so a failed rebuild needs no stamp.
        index.borrow_mut().note_trees_rebuilt(high_water);
        // The rebuild completed with no whole-scan fault and no per-entity gap: the index set is once
        // again a faithful image of the store, so a previous `fail_closed` is repaired (`rmp` task #733).
        // This is what lets a process self-heal from a *transient* storage fault instead of serving
        // scan-only (and reporting itself degraded) until it is restarted.
        index.borrow_mut().heal();
    }

    /// Whether `name` is already used by **any** schema catalog — a node-property index name, a
    /// full-text index, a spatial index, or a constraint (`rmp` task #624). The global name-uniqueness
    /// predicate a named `CREATE INDEX` consults before recording its name.
    fn name_in_use(store: &RecordStore<D, S>, name: &str) -> bool {
        store.node_property_index_name(name).is_some()
            || store.rel_property_index_name(name).is_some()
            || store.fulltext_index(name).is_some()
            || store.spatial_index(name).is_some()
            || store.constraint(name).is_some()
            || store.composite_index(name).is_some()
            || store.rel_composite_index(name).is_some()
            || store.text_index(name).is_some()
            || store.vector_index(name).is_some()
    }

    /// Whether `name` is used by a schema catalog **other than** `own` (`rmp` task #624). Lets a
    /// `CREATE` in the `own` catalog reject a cross-catalog name collision while preserving that
    /// catalog's own re-declare (replace) semantics for a name it already owns.
    fn name_used_by_other_catalog(store: &RecordStore<D, S>, name: &str, own: NameCatalog) -> bool {
        (own != NameCatalog::NodeProperty && store.node_property_index_name(name).is_some())
            || (own != NameCatalog::RelProperty && store.rel_property_index_name(name).is_some())
            || (own != NameCatalog::Fulltext && store.fulltext_index(name).is_some())
            || (own != NameCatalog::Spatial && store.spatial_index(name).is_some())
            || (own != NameCatalog::Constraint && store.constraint(name).is_some())
            || (own != NameCatalog::Composite && store.composite_index(name).is_some())
            || (own != NameCatalog::RelComposite && store.rel_composite_index(name).is_some())
            || (own != NameCatalog::Text && store.text_index(name).is_some())
            || (own != NameCatalog::Vector && store.vector_index(name).is_some())
    }

    /// Whether `name` is used by any schema rule **other than** the node-property index on
    /// `(label_token, prop_token)` (`rmp` task #624). Distinguishing "used by this same index" from
    /// "used by something else" is what keeps [`auto-naming`](auto_index_name) idempotent: recomputing
    /// the auto-name of an index that already carries that name is **not** a collision.
    fn name_used_by_other_target(
        store: &RecordStore<D, S>,
        name: &str,
        label_token: u32,
        prop_token: u32,
    ) -> bool {
        store.fulltext_index(name).is_some()
            || store.spatial_index(name).is_some()
            || store.constraint(name).is_some()
            || store.text_index(name).is_some()
            || store.vector_index(name).is_some()
            || matches!(
                store.node_property_index_name(name),
                Some(target) if target != (label_token, prop_token)
            )
    }

    /// A globally-unique, deterministic auto-name for the node-property index on `(label, property)`
    /// (`rmp` task #624). Returns the [`auto_index_name`] base when it is free (or already owned by this
    /// same index), else the deterministic token-suffixed form `<base>_<label_token>_<prop_token>` — the
    /// tokens uniquely identify the index, so the suffixed form is unique among auto-names.
    fn unique_auto_index_name(
        store: &RecordStore<D, S>,
        label: &str,
        property: &str,
        label_token: u32,
        prop_token: u32,
    ) -> String {
        let base = auto_index_name(label, property);
        if !Self::name_used_by_other_target(store, &base, label_token, prop_token) {
            return base;
        }
        // The token-suffixed form uniquely identifies the index *among auto-names*, but it can still
        // collide with an explicit, user-chosen name in any catalog. Verify the candidate is free and,
        // on a residual collision, iterate a deterministic counter until it is — so the returned name
        // is guaranteed unused by any *other* schema rule. Without this final check, a collision would
        // let two names map to the same target (a state `decode_index_name_catalog` rejects → the
        // store would fail to reopen) or let a nameless CREATE steal an existing index's name
        // (`rmp` #624 durability audit, HIGH + MEDIUM).
        let suffixed = format!("{base}_{label_token}_{prop_token}");
        if !Self::name_used_by_other_target(store, &suffixed, label_token, prop_token) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::name_used_by_other_target(store, &candidate, label_token, prop_token) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Whether `name` is used by any schema rule **other than** the relationship-property index on
    /// `(type_token, prop_token)` (`rmp` task #646) — the relationship analogue of
    /// [`name_used_by_other_target`](Self::name_used_by_other_target). Keeps a rel index's auto-name
    /// idempotent (recomputing an index's own name is not a collision).
    fn rel_name_used_by_other_target(
        store: &RecordStore<D, S>,
        name: &str,
        type_token: u32,
        prop_token: u32,
    ) -> bool {
        store.node_property_index_name(name).is_some()
            || store.fulltext_index(name).is_some()
            || store.spatial_index(name).is_some()
            || store.constraint(name).is_some()
            || store.text_index(name).is_some()
            || store.vector_index(name).is_some()
            || matches!(
                store.rel_property_index_name(name),
                Some(target) if target != (type_token, prop_token)
            )
    }

    /// A globally-unique, deterministic auto-name for the relationship-property index on
    /// `(rel_type, property)` (`rmp` task #646) — the relationship analogue of
    /// [`unique_auto_index_name`](Self::unique_auto_index_name). Returns the [`auto_rel_index_name`]
    /// base when free (or already owned by this same index), else the deterministic token-suffixed form,
    /// then a numeric counter — always verifying the candidate is free of *other* schema rules.
    fn unique_auto_rel_index_name(
        store: &RecordStore<D, S>,
        rel_type: &str,
        property: &str,
        type_token: u32,
        prop_token: u32,
    ) -> String {
        let base = auto_rel_index_name(rel_type, property);
        if !Self::rel_name_used_by_other_target(store, &base, type_token, prop_token) {
            return base;
        }
        let suffixed = format!("{base}_{type_token}_{prop_token}");
        if !Self::rel_name_used_by_other_target(store, &suffixed, type_token, prop_token) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::rel_name_used_by_other_target(store, &candidate, type_token, prop_token) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Inserts node `id`'s current composite tuples into every registered composite index whose covered
    /// label it carries and whose covered property tuple it holds **in full** (`rmp` task #100). The
    /// composite analogue of [`index_one_node`](Self::index_one_node): a node missing any covered
    /// property (or carrying a null for one) is **not** indexed for that key — matching the node-key
    /// rule that an incomplete tuple never participates in uniqueness. Store and index are borrowed in
    /// separate, non-overlapping scopes (the file's borrow discipline). Read faults skip best-effort.
    /// Decrements the front build's stall budget, returning whether it is now **exhausted** — i.e.
    /// whether the caller must poison (drop) the build (`rmp` task #733). A no-op returning `false` when
    /// the queue is empty.
    /// **Poisons** the front build: takes it off the pending queue (so the engine stops re-driving it and
    /// `has_pending_index_builds()` can go false — the termination guarantee) and parks it in the
    /// graveyard, counted (`rmp` task #733, M1). It is NOT discarded: once the store reads cleanly again,
    /// [`retry_poisoned_index_builds`](Self::retry_poisoned_index_builds) re-enqueues it from a fresh
    /// snapshot, so a transient fault costs a delay rather than a permanently dead index.
    fn poison_front<B>(queue: &mut VecDeque<B>, graveyard: &mut Vec<B>, events: &AtomicU64) {
        if let Some(build) = queue.pop_front() {
            graveyard.push(build);
            events.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn stall_or_poison<B>(queue: &mut VecDeque<B>, stall: impl Fn(&mut B) -> &mut u8) -> bool {
        let Some(front) = queue.front_mut() else {
            return false;
        };
        let budget = stall(front);
        // An already-exhausted budget stays exhausted (`rmp` task #733, L2). Testing `== 0` *after* a
        // saturating decrement would also poison a build that somehow started at `0` on its very first
        // stall — unreachable today (every build is enqueued at `BUILD_STALL_BUDGET`), but a trap for
        // whoever adds the next build kind. Spend a unit, then report exhaustion.
        if *budget == 0 {
            return true;
        }
        *budget -= 1;
        *budget == 0
    }

    /// Re-establishes a wiped build's snapshot from the **current** store (`rmp` task #733).
    ///
    /// Restarting a build at `cursor = 0` over its ORIGINAL snapshot is **not** enough, and believing it
    /// was is what left `rmp` #733 half-fixed. The original snapshot covered only the rows that existed
    /// when the build started; every row written *since* then was carried by
    /// [`RecordStoreGraph::reindex_node`](crate::record_graph) straight into the index's tree — and
    /// [`IndexSet::clear`] (which every rebuild runs, immediately before the scan that may fault)
    /// **destroys those maintenance writes along with everything else**. So at the moment of the wipe the
    /// tree is empty of post-snapshot rows too, and replaying only the old snapshot loses them *forever*,
    /// under an index that then promotes itself `Online`. A fresh scan is the only thing that covers both.
    ///
    /// Returns [`None`] when the store scan faults — the caller must then **poison** the build (drop it
    /// un-promoted, leaving the index `Populating` and therefore unused), never resume it.
    fn resnapshot_build(store: &SharedRef<RecordStore<D, S>>) -> Option<Vec<u64>> {
        // INVARIANT (`rmp` task #733, L1): every incremental build — node-property (`rmp` #91), full-text
        // (#72) and spatial (#98) — walks a snapshot of **node** ids, so one re-snapshot serves all three.
        // The relationship-covering indexes (rel-property, rel-composite, rel-full-text, rel-point,
        // rel-vector) are all built **synchronously** at create time and never enqueue an incremental
        // build, which is why no `scan_rel_ids` variant exists here. The day a relationship build becomes
        // incremental it MUST re-snapshot with `scan_rel_ids`: re-basing it on node ids would silently
        // index the wrong entities.
        store.borrow_mut().scan_node_ids().ok()
    }

    /// The **effective** state of an index, as the engine will actually treat it (`rmp` task #733) —
    /// the value every `SHOW INDEXES` surface must report.
    ///
    /// The durable catalog records what the schema *declares*; the in-memory [`IndexSet`] records what
    /// the engine can actually *use*. They diverge exactly when something went wrong: a build whose fill
    /// faulted stays `Populating` in memory while the catalog already says `ONLINE`, and a
    /// [`IndexSet::fail_closed`] demotes (or unregisters) every index while touching no durable byte.
    ///
    /// Reporting the durable state in those windows is not a cosmetic inaccuracy — it is a *false
    /// report of readiness*. An operator (or an automated `wait_for_indexes` poll, as the example
    /// harnesses use) that waits for `state != populating` would sail straight through a degraded
    /// engine, then attribute scan latencies to an index that is not being used. So an index that is not
    /// usable in memory reports `POPULATING`, whatever the catalog says: not usable, not online.
    ///
    /// `in_memory` is the kind's registered state, or [`None`] when the kind carries no state and its
    /// *registration* is its gate (composite, bitmap) — an unregistered one is reported `POPULATING`.
    fn effective_state(durable: IndexState, in_memory: Option<IndexState>) -> IndexState {
        match in_memory {
            // Usable in memory: the durable catalog is the truth (it may legitimately still say
            // `Populating` while an incremental build runs).
            Some(IndexState::Online) => durable,
            // Not registered, or registered but not `Online`: the engine will NOT use it.
            _ => IndexState::Populating,
        }
    }

    /// Records that a per-entity indexing helper **could not read an entity** and had to skip it
    /// (`rmp` task #733) — the shared reporting seam for every `index_one_*` helper.
    ///
    /// Skipping is safe only for an index that is *already published*: there, a missing candidate simply
    /// degrades that entity to a re-check. It is **not** safe while an index is being *built*: a seek can
    /// only drop candidates the index returns, never resurrect one it never returned, so an entity the
    /// build skipped is invisible to every label scan and every seek for the life of the process — a
    /// committed row silently lost to queries. The build that drove the helper reads this flag back and
    /// refuses to publish an index it knows is incomplete (a full rebuild goes
    /// [`IndexSet::fail_closed`]; an incremental build declines to promote itself `Online`).
    fn note_rebuild_gap(index: &SharedCell<IndexSet>) {
        index.borrow_mut().note_rebuild_gap();
    }

    fn index_one_node_composite(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, Vec<u32>)],
    ) {
        // The node's label tokens + EVERY candidate value of its properties (with the validity
        // interval each one is observable over), read in one store-borrow scope. Read-only:
        // `node_label_superset` / `superset_scan_node_properties` are `&self` (`rmp` #337 Slice 2).
        //
        // POLARITY — SUPERSET (`rmp` #766, #967). `superset_scan_node_properties` +
        // [`stamped_candidates`] rather than `cells_ignoring_history`: after `rmp` #967 an overwrite
        // is written IN PLACE and the old value descends onto the node's undo chain, so the live
        // cells are the CURRENT image and reading only them would silently drop every tuple an older
        // snapshot still needs — and for a NODE KEY that means the write path's duplicate check finds
        // nothing and ADMITS a committed duplicate (`rmp` #683 / #765). It is also not
        // `SupersetProperties::candidates`, which strips the stamps the per-view tuple construction
        // needs; see [`stamped_candidates`] for why a composite build cannot drop them.
        //
        // The membership gate is the LIVE-OR-RETAINED label superset, never the raw live word
        // (`rmp` task #904) — see `RecordStore::node_label_superset`.
        let (label_tokens, props, registry): (Vec<u32>, Vec<(u32, PropVersion)>, CommitRegistry) = {
            let store = store.borrow();
            let labels = match store.node_label_superset(id) {
                Ok(l) => l,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            // The node's own creation stamp is the `xmin` floor for a value whose installing write
            // has already been reclaimed off the undo chain (see [`stamped_candidates`]).
            let created_ts = match store.node(id) {
                Ok(rec) => rec.mvcc.created_ts,
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let chain = match store.superset_scan_node_properties(id) {
                Ok(chain) => stamped_candidates(&chain, created_ts),
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let mut props: Vec<(u32, PropVersion)> = Vec::with_capacity(chain.len());
            for cand in chain {
                match store.decode_property_value(cand.type_tag, cand.value_inline) {
                    Ok(value) => props.push((
                        cand.key,
                        PropVersion {
                            xmin: cand.xmin,
                            xmax: cand.xmax,
                            value,
                        },
                    )),
                    Err(_) => {
                        // `rmp` task #733: an undecodable version is a gap, not something to skip.
                        Self::note_rebuild_gap(index);
                        return;
                    }
                }
            }
            // The registry resolves lazily-stamped commits (see `visible_instant_range`).
            (labels, props, store.commit_registry_snapshot())
        };

        let mut idx = index.borrow_mut();
        for (label_token, property_tokens) in registered {
            if !label_tokens.contains(label_token) {
                continue; // node does not carry this composite index's label
            }
            // Every version chain of each covered property, newest first. A covered property with no
            // version at all can never form a tuple from any view, so the node is left unindexed here.
            let mut per_key: Vec<Vec<&PropVersion>> = Vec::with_capacity(property_tokens.len());
            let mut any_version = true;
            for prop_key in property_tokens {
                let versions: Vec<&PropVersion> = props
                    .iter()
                    .filter(|(k, _)| k == prop_key)
                    .map(|(_, v)| v)
                    .collect();
                if versions.is_empty() {
                    any_version = false;
                    break;
                }
                per_key.push(versions);
            }
            if any_version {
                // One tuple per observable VIEW (`rmp` task #766) — see `composite_candidate_tuples`
                // for why that is a complete superset, and why the in-flight writers need their own
                // views. Collapsing to the single newest version of each key indexed ONE tuple, a false
                // negative for every reader resolving a different one; because this tree backs NODE KEY,
                // that missing candidate makes the write path's duplicate check ADMIT A COMMITTED
                // DUPLICATE (`rmp` #765 / #683).
                // An unresolvable stamp (`rmp` #1069) marks the build INCOMPLETE and stops,
                // exactly as the store-read faults above do (`rmp` #733): an index published over
                // candidates nobody could compute would let the write path admit a committed
                // duplicate on a KEY constraint.
                let tuples = match composite_candidate_tuples(&per_key, &registry) {
                    Ok(t) => t,
                    // Marked through the guard ALREADY HELD, never `Self::note_rebuild_gap(index)`:
                    // that helper re-acquires the same `SharedCell`, which is a re-entrant
                    // acquisition — a deadlock in release and a tripwire panic in debug (`rmp` #1010).
                    Err(_) => {
                        idx.note_rebuild_gap();
                        return;
                    }
                };
                for tuple in tuples {
                    idx.insert_composite(
                        IndexWriter::Population,
                        *label_token,
                        property_tokens,
                        &tuple,
                        id,
                    );
                }
            }
        }
    }

    /// Inserts node `id`'s current label tokens and indexed property values into `index`, for the
    /// set of `registered` `(label_token, prop_key)` indexes. The store and the index are borrowed in
    /// **separate, non-overlapping** scopes (the load-bearing borrow discipline of this file).
    ///
    /// Extracted so the full-store rebuild ([`rebuild_index`](Self::rebuild_index)) and the
    /// incremental non-blocking build ([`advance_index_builds`](Self::advance_index_builds)) index a
    /// node through **exactly one** code path — the per-node logic cannot drift between them. A
    /// store-read fault on this node (an overflow-form bitmap, a non-storable value, a reclaimed slot)
    /// skips that node's entries best-effort: a missing candidate degrades that node to the full-scan
    /// fallback for a reader, never to a wrong row (the candidate-set contract).
    fn index_one_node(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // Read this node's label-membership SUPERSET — the live word widened by every label an
        // `AddLabel` delta on its undo chain could restore (`rmp` task #904) — in a store borrow
        // released before the index borrow.
        //
        // # Why the superset and not the live word (`rmp` task #904)
        //
        // The live word is mutated IN PLACE, so it carries an uncommitted writer's changes and is
        // neither the committed set nor the one a future reader will see. Gating on it made this refill
        // a SUBSET in exactly the way the version loop below is written to avoid: a refill run while a
        // writer held an uncommitted `REMOVE n:L` skipped the node for every `(L, *)` index, the entry
        // `clear` had just wiped was never re-inserted, and the writer's rollback restored the record's
        // label bit but nothing restored the entry — the same asymmetry, one level up. The victim was a
        // committed row lost to every seek for the life of the process, and — because `unique_conflict`
        // reads this tree as an EXACT candidate source and treats `Some([])` as "no duplicate" — a live
        // `IS UNIQUE` constraint that then admitted a duplicate. See `RecordStore::node_label_superset`.
        let label_tokens = match store.borrow_mut().node_label_superset(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // overflow-form bitmap or read fault: skip this node's entries.
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };

        // Resolve the node's property values, keyed by prop-key, so the index borrow below never
        // overlaps a store borrow. `superset_scan_node_property_values` decodes the whole chain
        // newest-first (`rmp` task #50): it holds EVERY not-yet-GC'd version of every key — the
        // live one, the versions an older snapshot still reads, and any still-uncommitted write.
        //
        // # Index EVERY version, never just the newest (`rmp` task #766)
        //
        // This loop indexes **one entry per version**, with no newest-wins collapse and no visibility
        // filter. That is what makes the refill a candidate **SUPERSET**, which is the only image this
        // index may hold, because of the asymmetry stated above: a seek's re-check can REMOVE a
        // candidate, never RESURRECT one. An extra entry (an uncommitted, stale, or aborted version) is
        // a false POSITIVE the re-check drops; a missing entry is a committed row silently lost.
        //
        // Newest-wins produced a SUBSET, and lost committed rows two ways (both reproduced, and pinned
        // by `tests/index_rebuild_uncommitted.rs`):
        //   - the newest version may be UNCOMMITTED, so the committed value was never indexed at all
        //     and a FRESH reader — precisely the reader the `rmp` #765 watermark declares safe — sought
        //     it and got nothing;
        //   - the versions an OLDER snapshot resolves were dropped, which is the `rmp` #765 defect.
        // Reading the newest *committed* version instead only moves the victim: the in-flight writer's
        // own value would then be missing, and `commit` does not re-insert index entries (they are made
        // eagerly at write time), so that row stays lost once the writer commits. Indexing every version
        // is the only image that serves both readers.
        let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().superset_scan_node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // a non-storable / read fault: skip this node's properties.
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                // Only keep keys that a registered index over one of this node's labels uses. NOTE: no
                // dedup by key — every version of a used key is indexed (`rmp` task #766).
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for &lt in &label_tokens {
            index.insert_label(IndexWriter::Population, lt, id);
        }
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_node_property(lt, *prop_key) {
                    index.insert_node_property(IndexWriter::Population, lt, *prop_key, value, id);
                }
            }
        }
    }

    /// Inserts relationship `id`'s current property values into every registered relationship-property
    /// index whose covered type it carries (`rmp` task #646) — the relationship analogue of
    /// [`index_one_node`](Self::index_one_node). Candidate-only, exactly like the node path: only the
    /// current value is inserted (a seek re-checks visibility, current type and current value), so no
    /// stale-entry removal is needed. Store and index are borrowed in separate, non-overlapping scopes
    /// (the file's borrow discipline); a read fault skips this relationship best-effort.
    fn index_one_rel(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // The relationship's current type token (store borrow, released before the index borrow).
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // read fault: skip this relationship's entries.
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // Nothing registered for this type ⇒ nothing to index (avoid the property-chain decode).
        if !registered
            .iter()
            .any(|&(reg_type, _)| reg_type == type_token)
        {
            return;
        }

        // Resolve the relationship's property values, keeping only the keys a registered index over this
        // relationship's type uses. Like the node path, this indexes **every version** in the chain with
        // no newest-wins collapse (`rmp` task #766): the tree must be a candidate SUPERSET, because a
        // seek's re-check can remove a candidate but never resurrect one. Collapsing to the newest
        // version dropped the committed value whenever the head was an uncommitted write — and this tree
        // backs relationship uniqueness / REL KEY enforcement, where a missing candidate is not merely a
        // lost row but an ADMITTED COMMITTED DUPLICATE (the `rmp` #683 / #765 failure mode).
        let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
        {
            let chain = match store.borrow().superset_scan_rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // a non-storable / read fault: skip this relationship's properties.
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                // No dedup by key: every version of a used key is indexed (`rmp` task #766).
                let used = registered
                    .iter()
                    .any(|&(reg_type, prop_key)| reg_type == type_token && prop_key == key);
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            index.insert_rel_property(IndexWriter::Population, type_token, *prop_key, value, id);
        }
    }

    /// Inserts relationship `id`'s current composite tuple into every registered composite relationship
    /// index whose covered type it carries (`rmp` task #666) — the relationship analogue of
    /// [`index_one_node_composite`](Self::index_one_node_composite). Candidate-only: only the current
    /// tuple is inserted (a seek re-checks visibility, current type and current tuple), so no stale-entry
    /// removal is needed — stale entries are false POSITIVES the re-check drops. The converse does NOT
    /// follow: because only the current tuple is inserted, this refill cannot restore the stale entries
    /// [`IndexSet::clear`] destroyed, which an OLDER snapshot needs (`rmp` #765) — hence the
    /// [`IndexSet::note_trees_rebuilt`] stamp that makes such a reader decline to the exact scan.
    /// Store and index are borrowed in separate, non-overlapping scopes; a read fault
    /// skips this relationship best-effort. A relationship missing a covered property (an incomplete
    /// tuple) is left unindexed for that key.
    fn index_one_rel_composite(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, Vec<u32>)],
    ) {
        // The relationship's current type token (store borrow released before the index borrow).
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // read fault: skip this relationship's entries.
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // Nothing registered for this type ⇒ nothing to index (avoid the property-chain decode).
        if !registered
            .iter()
            .any(|(reg_type, _)| *reg_type == type_token)
        {
            return;
        }
        // POLARITY — SUPERSET (`rmp` #766, #967), the relationship twin of
        // `index_one_node_composite`: EVERY candidate value of the relationship's properties with the
        // validity interval each is observable over. `superset_scan_rel_properties` +
        // [`stamped_candidates`] rather than the live cells (which after `rmp` #967 are only the
        // CURRENT image, so a REL KEY would lose the candidate that catches a committed duplicate —
        // `rmp` #683) and rather than `superset_scan_rel_property_values`, which strips the stamps
        // the per-view tuple construction needs.
        let (props, registry): (Vec<(u32, PropVersion)>, CommitRegistry) = {
            let store = store.borrow();
            // The relationship's own creation stamp is the `xmin` floor for a value whose installing
            // write has already been reclaimed off the undo chain (see [`stamped_candidates`]).
            let created_ts = match store.rel(id) {
                Ok(rec) => rec.mvcc.created_ts,
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let chain = match store.superset_scan_rel_properties(id) {
                Ok(chain) => stamped_candidates(&chain, created_ts),
                Err(_) => {
                    // a non-storable / read fault: skip this relationship's properties.
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let mut out: Vec<(u32, PropVersion)> = Vec::with_capacity(chain.len());
            for cand in chain {
                match store.decode_property_value(cand.type_tag, cand.value_inline) {
                    Ok(value) => out.push((
                        cand.key,
                        PropVersion {
                            xmin: cand.xmin,
                            xmax: cand.xmax,
                            value,
                        },
                    )),
                    Err(_) => {
                        // `rmp` task #733: an undecodable version is a gap, not something to skip.
                        Self::note_rebuild_gap(index);
                        return;
                    }
                }
            }
            // The registry resolves lazily-stamped commits (see `visible_instant_range`).
            (out, store.commit_registry_snapshot())
        };

        let mut idx = index.borrow_mut();
        for (reg_type, property_tokens) in registered {
            if *reg_type != type_token {
                continue; // relationship does not carry this composite index's type
            }
            // Every version chain of each covered property, newest first; a covered property with no
            // version at all can form no tuple from any view.
            let mut per_key: Vec<Vec<&PropVersion>> = Vec::with_capacity(property_tokens.len());
            let mut any_version = true;
            for prop_key in property_tokens {
                let versions: Vec<&PropVersion> = props
                    .iter()
                    .filter(|(k, _)| k == prop_key)
                    .map(|(_, v)| v)
                    .collect();
                if versions.is_empty() {
                    any_version = false;
                    break;
                }
                per_key.push(versions);
            }
            if any_version {
                // One tuple per observable view — the construction of `composite_candidate_tuples`,
                // applied to the relationship tree (`rmp` task #766).
                // An unresolvable stamp (`rmp` #1069) marks the build INCOMPLETE and stops,
                // exactly as the store-read faults above do (`rmp` #733): an index published over
                // candidates nobody could compute would let the write path admit a committed
                // duplicate on a KEY constraint.
                let tuples = match composite_candidate_tuples(&per_key, &registry) {
                    Ok(t) => t,
                    // Marked through the guard ALREADY HELD, never `Self::note_rebuild_gap(index)`:
                    // that helper re-acquires the same `SharedCell`, which is a re-entrant
                    // acquisition — a deadlock in release and a tripwire panic in debug (`rmp` #1010).
                    Err(_) => {
                        idx.note_rebuild_gap();
                        return;
                    }
                };
                for tuple in tuples {
                    idx.insert_rel_composite(
                        IndexWriter::Population,
                        type_token,
                        property_tokens,
                        &tuple,
                        id,
                    );
                }
            }
        }
    }

    /// Re-indexes node `id` in **every** registered full-text index from its current label tokens and
    /// **string** property values (`rmp` task #72). The full-text analogue of
    /// [`index_one_node`](Self::index_one_node): the same single per-node code path the full rebuild
    /// ([`rebuild_index`](Self::rebuild_index)) and the non-blocking full-text build
    /// ([`advance_index_builds`](Self::advance_index_builds)) both drive, so their per-node logic can
    /// never diverge.
    ///
    /// Unlike `index_one_node` it reads **all** of the node's string property values (not just those a
    /// registered property index uses), because which properties a full-text index covers is a
    /// per-index decision the [`IndexSet`] applies; the value class is filtered to strings here (a
    /// full-text index covers text). The store and the index are borrowed in **separate,
    /// non-overlapping** scopes, the load-bearing discipline of this file. A read fault on the node
    /// skips it best-effort (the candidate-set contract: a missing candidate degrades to the
    /// scan-and-filter fallback for that reader, never a wrong row).
    fn index_one_node_fulltext(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
    ) {
        // Read the node's label-membership SUPERSET (`rmp` task #904 — the live word widened by every
        // label an `AddLabel` delta on its undo chain could restore, never the raw live word; see
        // `RecordStore::node_label_superset`), the covered full-text keys and its live property CELLS
        // in one shared borrow scope (`node_label_superset` / `superset_scan_node_properties` are
        // `&self`, `rmp` #337 Slice 2).
        //
        // POLARITY — CURRENT IMAGE, deliberately (`cells_ignoring_history`, `rmp` #778 option (b),
        // #967). A full-text document is indexed WHOLE, and `fulltext_query` re-checks a hit's
        // visibility and current label but NEVER its terms, so a term unioned in from an older version
        // is a wrong row the consumer cannot drop — the opposite of the text / spatial grids, which
        // index each value independently and therefore DO take the union (`rmp` #773 / #779). This
        // build has never been a superset for that reason; what makes it safe is the in-flight-writer
        // gate below, which refuses to bake at all while the newest version of a covered key is
        // uncommitted. `cells_ignoring_history` is the read that expresses exactly that image: after
        // `rmp` #967 the live cells ARE the current value of every key (an overwrite rewrites the cell
        // in place, a removal empties it), and it keeps the EMPTY cells the gate below needs — which
        // `SupersetProperties::candidates` drops, taking the removal half of the gate's window with it.
        let (label_tokens, covered, chain) = {
            let store = store.borrow();
            let label_tokens = match store.node_label_superset(id) {
                Ok(tokens) => tokens,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let covered = index
                .borrow()
                .fulltext_covered_keys_for_labels(&label_tokens);
            let chain = match store.superset_scan_node_properties(id) {
                Ok(chain) => chain.cells_ignoring_history().to_vec(),
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            (label_tokens, covered, chain)
        };

        // Option (b), `rmp` task #778 (poison-on-build). If an in-flight transaction holds the NEWEST
        // version of a covered property, baking newest-wins would index its uncommitted value and lose
        // the committed one — the #766 loss the full-text consumer cannot repair (it re-checks
        // visibility + label but NOT terms). Record the conflict and do NOT bake this node, so the build
        // stays `Populating` (readers decline to the snapshot-correct scan) until the writer resolves.
        // An unresolvable stamp (`rmp` #1069) makes the gate unanswerable, so the build is marked
        // INCOMPLETE and stops — the same fail-closed answer the store-read faults above give
        // (`rmp` #733). Reading it as "no active writer" would promote the index over a value the
        // gate never got to judge, which is the #766 loss this gate exists to prevent.
        // The registry is borrowed as a READ GUARD, not cloned: this runs once per entity in an
        // O(store) rebuild, and `is_txn_active` reads the Active Transaction Table, never the
        // registry, so holding it across the closure cannot self-deadlock.
        let conflicting_writer = {
            let registry = store.borrow().commit_registry();
            match active_writer_holds_newest_covered(&chain, &covered, &registry, |w| {
                store.borrow().is_txn_active(w)
            }) {
                Ok(w) => w,
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            }
        };
        if let Some(writer) = conflicting_writer {
            index.borrow_mut().note_ft_build_conflict(writer);
            return;
        }

        // The node's current string property values, keyed by prop-key (newest-wins per key).
        let mut string_props: Vec<(u32, String)> = Vec::new();
        {
            let store = store.borrow();
            // `seen` is tracked SEPARATELY from `string_props`, and both skips below happen BEFORE the
            // decode. Three distinct correctness points, each measured (`rmp` task #778 audit):
            //
            // 1. NEWEST-WINS ACROSS TYPES. Keying "already handled" off `string_props` made the guard
            //    trip only once a *String* had been pushed, so when the newest version of a key was a
            //    non-string the loop walked on and indexed an OLDER string version of that same key:
            //    `SET n.title = 42` over a committed `'alpha'` left the index still matching `'alpha'`.
            //    A key is settled by its newest version whatever that version's type.
            // 2. A COMMITTED REMOVAL IS NOT PART OF THE STATE. A removed property's value must not stay
            //    indexable: `REMOVE n.title` committed, then any rebuild re-baked `'alpha'`. Before
            //    `rmp` #967 the removal was an in-place TOMBSTONE, so a non-zero `expired_ts` was the
            //    signal; after #967 (`D-property-removal`) it is the cell rewritten in place to the
            //    EMPTY form, so the signal is `type_tag == TYPE_TAG_ABSENT` and `expired_ts` is never
            //    written by a property operation again. The still-in-flight case is already parked by
            //    the conflict gate above, so reaching here with an empty cell means the remover
            //    committed.
            // 3. FAIL-CLOSED NARROWING. Skipping before the decode means a corrupt SHADOWED or REMOVED
            //    version no longer raises a `rebuild_gap` (`rmp` task #733). Deliberate: only the newest
            //    live version reaches the index, so neither can make the index an inexact image of the
            //    committed store — which is the condition `rebuild_gap` exists to detect.
            let mut seen: Vec<u32> = Vec::new();
            for (_pid, prop) in &chain {
                if seen.contains(&prop.key) {
                    continue;
                }
                seen.push(prop.key);
                if prop.type_tag == TYPE_TAG_ABSENT || prop.mvcc.expired_ts != 0 {
                    continue;
                }
                match store.decode_property_value(prop.type_tag, prop.value_inline) {
                    Ok(graphus_core::Value::String(s)) => string_props.push((prop.key, s)),
                    Ok(_) => {} // a full-text index covers string text only
                    Err(_) => {
                        Self::note_rebuild_gap(index);
                        return;
                    }
                }
            }
        }
        index
            .borrow_mut()
            .reindex_fulltext_node(id, &label_tokens, &string_props);
    }

    /// Re-indexes relationship `id` in **every** registered relationship full-text index from its
    /// current type token and **string** property values (`rmp` task #663) — the relationship analogue
    /// of [`index_one_node_fulltext`](Self::index_one_node_fulltext). Read faults skip the relationship
    /// best-effort (the candidate-set contract). The store and the index are borrowed in **separate,
    /// non-overlapping** scopes, the load-bearing discipline of this file.
    fn index_one_rel_fulltext(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
    ) {
        // The relationship's type, covered full-text keys and live property CELLS in one shared borrow
        // scope — the relationship twin of `index_one_node_fulltext` (`rmp` tasks #778, #967), with the
        // same polarity and the same reason: a full-text document is indexed whole and its consumer
        // never re-checks terms, so this build bakes the CURRENT image (`cells_ignoring_history`) and
        // refuses to bake at all while an in-flight writer holds the newest version of a covered key.
        // Read that method's comment for the full argument, including why the EMPTY cells the gate
        // needs make `SupersetProperties::candidates` the wrong read here.
        let (type_token, covered, chain) = {
            let store = store.borrow();
            let type_token = match store.rel(id) {
                Ok(r) => r.type_id,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let covered = index
                .borrow()
                .fulltext_rel_covered_keys_for_type(type_token);
            let chain = match store.superset_scan_rel_properties(id) {
                Ok(chain) => chain.cells_ignoring_history().to_vec(),
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            (type_token, covered, chain)
        };

        // Option (b), `rmp` task #778 (poison-on-build) — the relationship twin of the node gate. An
        // in-flight writer holding the newest version of a covered property means a newest-wins bake
        // would lose the committed value, so record the conflict and do NOT bake (the build stays
        // `Populating`, readers decline to the scan) until the writer resolves.
        // An unresolvable stamp (`rmp` #1069) makes the gate unanswerable, so the build is marked
        // INCOMPLETE and stops — the same fail-closed answer the store-read faults above give
        // (`rmp` #733). Reading it as "no active writer" would promote the index over a value the
        // gate never got to judge, which is the #766 loss this gate exists to prevent.
        // The registry is borrowed as a READ GUARD, not cloned: this runs once per entity in an
        // O(store) rebuild, and `is_txn_active` reads the Active Transaction Table, never the
        // registry, so holding it across the closure cannot self-deadlock.
        let conflicting_writer = {
            let registry = store.borrow().commit_registry();
            match active_writer_holds_newest_covered(&chain, &covered, &registry, |w| {
                store.borrow().is_txn_active(w)
            }) {
                Ok(w) => w,
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            }
        };
        if let Some(writer) = conflicting_writer {
            index.borrow_mut().note_ft_build_conflict(writer);
            return;
        }

        // The relationship's current string property values, keyed by prop-key (newest-wins per key).
        let mut string_props: Vec<(u32, String)> = Vec::new();
        {
            let store = store.borrow();
            // `seen` is tracked SEPARATELY from `string_props`, and both skips below happen BEFORE the
            // decode. Three distinct correctness points, each measured (`rmp` task #778 audit):
            //
            // 1. NEWEST-WINS ACROSS TYPES. Keying "already handled" off `string_props` made the guard
            //    trip only once a *String* had been pushed, so when the newest version of a key was a
            //    non-string the loop walked on and indexed an OLDER string version of that same key:
            //    `SET n.title = 42` over a committed `'alpha'` left the index still matching `'alpha'`.
            //    A key is settled by its newest version whatever that version's type.
            // 2. A COMMITTED REMOVAL IS NOT PART OF THE STATE. A removed property's value must not stay
            //    indexable: `REMOVE n.title` committed, then any rebuild re-baked `'alpha'`. Before
            //    `rmp` #967 the removal was an in-place TOMBSTONE, so a non-zero `expired_ts` was the
            //    signal; after #967 (`D-property-removal`) it is the cell rewritten in place to the
            //    EMPTY form, so the signal is `type_tag == TYPE_TAG_ABSENT` and `expired_ts` is never
            //    written by a property operation again. The still-in-flight case is already parked by
            //    the conflict gate above, so reaching here with an empty cell means the remover
            //    committed.
            // 3. FAIL-CLOSED NARROWING. Skipping before the decode means a corrupt SHADOWED or REMOVED
            //    version no longer raises a `rebuild_gap` (`rmp` task #733). Deliberate: only the newest
            //    live version reaches the index, so neither can make the index an inexact image of the
            //    committed store — which is the condition `rebuild_gap` exists to detect.
            let mut seen: Vec<u32> = Vec::new();
            for (_pid, prop) in &chain {
                if seen.contains(&prop.key) {
                    continue;
                }
                seen.push(prop.key);
                if prop.type_tag == TYPE_TAG_ABSENT || prop.mvcc.expired_ts != 0 {
                    continue;
                }
                match store.decode_property_value(prop.type_tag, prop.value_inline) {
                    Ok(graphus_core::Value::String(s)) => string_props.push((prop.key, s)),
                    Ok(_) => {} // a full-text index covers string text only
                    Err(_) => {
                        Self::note_rebuild_gap(index);
                        return;
                    }
                }
            }
        }
        index
            .borrow_mut()
            .reindex_fulltext_rel(id, type_token, &string_props);
    }

    /// Indexes relationship `id`'s **every** point version into each `registered`
    /// `(type_token, prop_key)` relationship spatial index it matches (`rmp` tasks #664 / #779). The
    /// relationship analogue of [`index_one_node_spatial`](Self::index_one_node_spatial): the same
    /// single per-relationship code path the full rebuild ([`rebuild_index`](Self::rebuild_index)) and
    /// the synchronous create build both drive, so a recovered store rebuilds the relationship grids
    /// store-consistently. Only the **point**-valued properties a registered index covers are read; a
    /// relationship of a different type, or whose covered property is absent / non-point, contributes
    /// nothing (the grid is a candidate set). The store and index are borrowed in **separate,
    /// non-overlapping** scopes.
    ///
    /// Like the node twin it **unions every version** rather than collapsing newest-wins — see
    /// [`index_one_node_spatial`](Self::index_one_node_spatial) for why that is the only safe image
    /// (`rmp` #766/#779).
    fn index_one_rel_spatial(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // EVERY point version a registered relationship spatial index covers for this relationship's
        // type, in chain order (newest first) — NOT collapsed newest-wins (`rmp` task #779).
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow().superset_scan_rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                // EVERY point version, not just the newest (`rmp` task #779) — see the node twin
                // `index_one_node_spatial`'s docs. No newest-wins dedup here: the union below is what
                // makes the grid a candidate SUPERSET across versions.
                let used = registered
                    .iter()
                    .any(|&(reg_type, prop_key)| prop_key == key && reg_type == type_token);
                if used && matches!(value, Value::Point(_)) {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            if index.has_spatial_rel(type_token, *prop_key) {
                index.merge_spatial_rel_point(type_token, *prop_key, value, id);
            }
        }
    }

    /// Indexes node `id`'s **every** point version into each `registered` `(label_token, prop_key)`
    /// spatial index it matches (`rmp` tasks #98 / #779). The spatial analogue of
    /// [`index_one_node`](Self::index_one_node) / [`index_one_node_text`](Self::index_one_node_text):
    /// the same single per-node code path the full rebuild ([`rebuild_index`](Self::rebuild_index)) and
    /// the non-blocking spatial build ([`advance_spatial_build`](Self::advance_spatial_build)) both
    /// drive, so their per-node logic can never diverge.
    ///
    /// Only the **point**-valued properties a registered index covers are read; a node that does not
    /// carry the covered label, or whose covered property is absent / non-point, contributes nothing
    /// (the grid is a candidate set, so a missing candidate degrades to the scan fallback for that
    /// reader — never a wrong row). The store and the index are borrowed in **separate,
    /// non-overlapping** scopes (the load-bearing borrow discipline of this file).
    ///
    /// # Index EVERY version, never just the newest (`rmp` task #779)
    ///
    /// The chain is decoded newest-first and each point version is **unioned** into the grid via
    /// [`merge_spatial_point`](IndexSet::merge_spatial_point), so the grid becomes a candidate
    /// **SUPERSET** across all versions — for the same reason as the text index (`rmp` #773) and with
    /// the same false-negative asymmetry behind it: a seek's residual re-check can REMOVE a candidate,
    /// never RESURRECT one. Collapsing to the newest version produced a SUBSET, and when that newest
    /// version belonged to a still-open transaction the committed point was indexed nowhere and a fresh
    /// reader sought it and got nothing — the #766 loss, which reproduced on this grid until this fix
    /// (pinned by `tests/index_rebuild_uncommitted.rs`). The extra cells a union occupies are false
    /// positives the executor's residual `distance(...) <op> r` filter drops, re-reading each
    /// candidate's snapshot-visible point.
    ///
    /// This is the **build** path only; the per-write seam ([`reindex_node`](crate::record_graph) →
    /// [`insert_spatial_point`](IndexSet::insert_spatial_point)) stays last-wins, feeding one current
    /// point per key, so the union engages solely here.
    fn index_one_node_spatial(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // `rmp` task #904: the membership gate is the LIVE-OR-RETAINED label superset, never the raw
        // live word — see `RecordStore::node_label_superset` for why a refill must not read the word an
        // uncommitted `REMOVE n:L` is sitting on.
        let label_tokens = match store.borrow_mut().node_label_superset(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // EVERY point version a registered spatial index covers for one of this node's labels, in
        // chain order (newest first) — NOT collapsed newest-wins (`rmp` task #779).
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().superset_scan_node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                // EVERY point version, not just the newest (`rmp` task #779). No newest-wins dedup: the
                // union below is what makes the grid a candidate SUPERSET across versions.
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used && matches!(value, Value::Point(_)) {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_spatial(lt, *prop_key) {
                    index.merge_spatial_point(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// Indexes node `id`'s **every** string version into each `registered` `(label_token, prop_key)`
    /// text (trigram) index it matches (`rmp` tasks #662 / #773). The text analogue of
    /// [`index_one_node_spatial`](Self::index_one_node_spatial): the same single per-node code path the
    /// full rebuild ([`rebuild_index`](Self::rebuild_index)) and the synchronous create build both drive,
    /// so a recovered store rebuilds the trigram indexes store-consistently. Only the **string**-valued
    /// versions a registered index covers are read; a node not carrying the covered label, or whose
    /// covered property is absent / non-string, contributes nothing.
    ///
    /// # Index EVERY version, never just the newest (`rmp` task #773)
    ///
    /// The chain is decoded newest-first and each string version is **unioned** into the trigram tree
    /// via [`merge_text_value`](IndexSet::merge_text_value), so the tree becomes a candidate **SUPERSET**
    /// across all versions. This is the only image the tree may hold, because of the false-negative
    /// asymmetry the whole index layer turns on: a seek's residual re-check can REMOVE a candidate, never
    /// RESURRECT one. Collapsing to the newest version produced a SUBSET, and when that newest version
    /// belonged to a still-open transaction (an index built while a writer holds an uncommitted
    /// overwrite) the committed value was indexed nowhere and a fresh reader sought it and got nothing —
    /// the #766 loss, which reproduced on this tree until this fix (pinned by
    /// `tests/index_rebuild_uncommitted.rs`). The extra trigrams a superset carries are false positives
    /// the executor's residual `CONTAINS`/`STARTS WITH`/`ENDS WITH` filter drops, re-reading each
    /// candidate's snapshot-visible value.
    ///
    /// This is the **build** path only; the per-write seam ([`reindex_node`](crate::record_graph) →
    /// [`insert_text_value`](IndexSet::insert_text_value)) stays last-wins, feeding one current value per
    /// key, so the union engages solely here. The store and index are borrowed in **separate,
    /// non-overlapping** scopes (this file's borrow discipline).
    fn index_one_node_text(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // `rmp` task #904: the membership gate is the LIVE-OR-RETAINED label superset, never the raw
        // live word — see `RecordStore::node_label_superset` for why a refill must not read the word an
        // uncommitted `REMOVE n:L` is sitting on.
        let label_tokens = match store.borrow_mut().node_label_superset(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // EVERY string version of a covered key for one of this node's labels — no newest-wins collapse
        // (`rmp` task #773), keeping only string values (a text index covers strings only).
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().superset_scan_node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                // No dedup by key — every string version is unioned into the tree (`rmp` task #773).
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used && matches!(value, Value::String(_)) {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_text(lt, *prop_key) {
                    index.merge_text_value(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// (Re)indexes node `id`'s current embedding into each `registered` `(label_token, prop_key)` vector
    /// (HNSW) index it matches (`rmp` task #669). The vector analogue of
    /// [`index_one_node_text`](Self::index_one_node_text): the same single per-node code path the full
    /// rebuild ([`rebuild_index`](Self::rebuild_index)) drives, so a recovered store rebuilds the ANN
    /// graphs store-consistently. Only the covered property is read; its value is handed verbatim to
    /// [`insert_vector_value`](crate::index_set::IndexSet::insert_vector_value), which indexes it iff it
    /// is a valid embedding (a numeric list of the declared dimension) and otherwise leaves the node out
    /// — so a node not carrying the covered label, or whose covered property is absent / malformed,
    /// contributes nothing. Store and index are borrowed in **separate, non-overlapping** scopes.
    fn index_one_node_vector(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // `rmp` task #904: the membership gate is the LIVE-OR-RETAINED label superset, never the raw
        // live word — see `RecordStore::node_label_superset` for why a refill must not read the word an
        // uncommitted `REMOVE n:L` is sitting on.
        let label_tokens = match store.borrow_mut().node_label_superset(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };

        // `rmp` task #780 — the #766 uncommitted-version gate, per covered index.
        //
        // The loop below collapses the property chain NEWEST-WINS. If the newest version of a covered
        // embedding belongs to a still-ACTIVE writer, baking it indexes an UNCOMMITTED embedding and
        // leaves the committed one indexed nowhere — MEASURED to make a fresh reader's k=1 return the
        // wrong node, with a `score` computed from a vector that reader's snapshot cannot see (a dirty
        // read, not a recall artifact), and to SURVIVE that writer's rollback for the life of the
        // process. Unlike full-text (`rmp` #778) the consumer cannot repair it: the per-candidate
        // re-check validates the embedding's SHAPE, never its geometry.
        //
        // So: skip the entity AND record the writer against each index that covers it. A non-empty
        // blocker list makes every reader of that index decline to the exact brute-force scan until a
        // conflict-free re-fill succeeds. Attribution is per `(token, prop_key)` rather than global so
        // one conflicted index never makes an unrelated one decline.
        //
        // The liveness predicate is the store's Active Transaction Table
        // (`RecordStore::is_txn_active`), deliberately NOT `CommitRegistry::outcome(w) ==
        // TxnOutcome::InFlight`, which is DEAD — always false, since the registry gains an entry only
        // when a transaction *resolves*. That exact confusion is `rmp` #522 and it silently no-opped the
        // pre-#778 full-text gate; re-making it here would no-op this one.
        //
        // POLARITY — CURRENT IMAGE for the GATE (`cells_ignoring_history`, `rmp` #967). The question
        // this read answers is structural: "does a still-open transaction hold the newest version of a
        // covered key?". After #967 that writer's mark is the CELL's own `created_ts`, restamped in
        // place by a `SET` and by a `REMOVE` alike, so the gate reads the cells' MVCC headers — one of
        // the uses `SupersetProperties::cells_ignoring_history` names as legitimate. It is NOT
        // `candidates`, which drops the EMPTY cell a `REMOVE` leaves behind and would therefore reopen
        // the removal half of this window; and it is not a snapshot read, because a build has no
        // snapshot. The VALUES this build bakes are read separately below.
        let conflicted_keys: Vec<u32> = {
            let chain = match store.borrow().superset_scan_node_properties(id) {
                Ok(chain) => chain.cells_ignoring_history().to_vec(),
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let covering: Vec<(u32, u32)> = registered
                .iter()
                .copied()
                .filter(|(reg_label, _)| label_tokens.contains(reg_label))
                .collect();
            let mut keys = Vec::new();
            for (reg_label, prop_key) in covering {
                // Fail closed on an unresolvable stamp (`rmp` #1069 / #733), exactly as the chain
                // read above does: an unjudged key must not be baked as conflict-free.
                // A read guard, not a clone — see the full-text build for why.
                let conflicting_writer = {
                    let registry = store.borrow().commit_registry();
                    match active_writer_holds_newest_covered(&chain, &[prop_key], &registry, |w| {
                        store.borrow().is_txn_active(w)
                    }) {
                        Ok(w) => w,
                        Err(_) => {
                            Self::note_rebuild_gap(index);
                            return;
                        }
                    }
                };
                if let Some(writer) = conflicting_writer {
                    index
                        .borrow_mut()
                        .note_vector_build_conflict(reg_label, prop_key, writer);
                    if !keys.contains(&prop_key) {
                        keys.push(prop_key);
                    }
                }
            }
            keys
        };

        // The node's current property values, keyed by prop-key, keeping only the values a registered
        // vector index covers for one of this node's labels. The value type is NOT pre-filtered here
        // (unlike text/spatial): `insert_vector_value` validates the embedding shape.
        //
        // POLARITY — CURRENT IMAGE (`cells_ignoring_history`, `rmp` #967). An HNSW graph holds ONE
        // embedding per entity, so unlike the text / spatial grids it cannot union versions, and
        // `rmp` #780 already settled that an entity whose newest covered version is uncommitted is left
        // out entirely rather than indexed at an older one. After #967 the live cells ARE that current
        // image; reading `superset_scan_node_property_values` (which now yields the CANDIDATE superset —
        // cells first, then history) and keeping the first occurrence per key would re-bake a removed
        // embedding, because `candidates` drops the EMPTY cell a `REMOVE` leaves and the key's first
        // surviving candidate is then a historical value.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let store = store.borrow();
            let cells = match store.superset_scan_node_properties(id) {
                Ok(chain) => chain.cells_ignoring_history().to_vec(),
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, cell) in cells {
                if cell.type_tag == TYPE_TAG_ABSENT {
                    continue; // `REMOVE n.p` emptied the cell in place: the key is absent (`rmp` #967)
                }
                if values.iter().any(|(k, _)| *k == cell.key) {
                    continue; // one cell per key in a healthy store; keep the head deterministically
                }
                // `rmp` #780: an active writer holds this key's newest version. Indexing ANY version
                // here would be wrong — the newest is uncommitted, and an older one is not what a
                // newest-wins graph means — so leave the entity out entirely. The blocker recorded
                // above makes readers decline this index to the exact scan, which sees the committed
                // value, so the omission is never observable as a missing row.
                if conflicted_keys.contains(&cell.key) {
                    continue;
                }
                if !registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == cell.key && label_tokens.contains(&reg_label)
                }) {
                    continue;
                }
                // Decoded per COVERED key rather than over the whole chain, which narrows the `rmp` #733
                // fail-closed surface exactly as `decided_value_for_key` does: an unreadable overflow
                // chain belonging to a property no vector index covers can no longer block the build.
                match store.decode_property_value(cell.type_tag, cell.value_inline) {
                    Ok(value) => values.push((cell.key, value)),
                    Err(_) => {
                        Self::note_rebuild_gap(index);
                        return;
                    }
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                // Scope the fan-out to the `registered` set the CALLER asked for, not to "any vector
                // index that happens to cover this (label, key)" (`rmp` task #780 audit).
                //
                // `has_vector` alone was wrong for the partial re-fill driven by
                // `retry_conflicted_vector_builds`, which passes only the indexes it just WIPED: a node
                // carrying two covered labels would have had its embedding inserted into a sibling index
                // that was NOT wiped, silently duplicating maintenance into a graph the caller is not
                // rebuilding. The whole-set rebuild passes every registered key, so it is unaffected.
                if registered.contains(&(lt, *prop_key)) && index.has_vector(lt, *prop_key) {
                    index.insert_vector_value(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// (Re)indexes relationship `id`'s current embedding into each `registered` `(type_token, prop_key)`
    /// vector (HNSW) index it matches (`rmp` task #669) — the relationship analogue of
    /// [`index_one_node_vector`](Self::index_one_node_vector) (its structure mirrors
    /// [`index_one_rel_spatial`](Self::index_one_rel_spatial)).
    fn index_one_rel_vector(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // `rmp` task #780 — the relationship twin of the node gate in
        // [`index_one_node_vector`](Self::index_one_node_vector); see there for the full rationale,
        // including why the gate reads the live CELLS' MVCC headers (`cells_ignoring_history`,
        // `rmp` #967) rather than the candidate superset.
        let conflicted_keys: Vec<u32> = {
            let chain = match store.borrow().superset_scan_rel_properties(id) {
                Ok(chain) => chain.cells_ignoring_history().to_vec(),
                Err(_) => {
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let mut keys = Vec::new();
            for (reg_type, prop_key) in registered.iter().copied() {
                if reg_type != type_token {
                    continue;
                }
                // Fail closed on an unresolvable stamp (`rmp` #1069 / #733), exactly as the chain
                // read above does: an unjudged key must not be baked as conflict-free.
                // A read guard, not a clone — see the full-text build for why.
                let conflicting_writer = {
                    let registry = store.borrow().commit_registry();
                    match active_writer_holds_newest_covered(&chain, &[prop_key], &registry, |w| {
                        store.borrow().is_txn_active(w)
                    }) {
                        Ok(w) => w,
                        Err(_) => {
                            Self::note_rebuild_gap(index);
                            return;
                        }
                    }
                };
                if let Some(writer) = conflicting_writer {
                    index
                        .borrow_mut()
                        .note_vector_rel_build_conflict(reg_type, prop_key, writer);
                    if !keys.contains(&prop_key) {
                        keys.push(prop_key);
                    }
                }
            }
            keys
        };

        // POLARITY — CURRENT IMAGE (`cells_ignoring_history`, `rmp` #967): the relationship twin of the
        // node vector build; see there for why an HNSW graph must read the current image and why the
        // candidate superset would re-bake a removed embedding.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let store = store.borrow();
            let cells = match store.superset_scan_rel_properties(id) {
                Ok(chain) => chain.cells_ignoring_history().to_vec(),
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, cell) in cells {
                if cell.type_tag == TYPE_TAG_ABSENT {
                    continue; // `REMOVE r.p` emptied the cell in place: the key is absent (`rmp` #967)
                }
                if values.iter().any(|(k, _)| *k == cell.key) {
                    continue; // one cell per key in a healthy store; keep the head deterministically
                }
                // `rmp` #780: see the node twin — leave a conflicted entity out entirely.
                if conflicted_keys.contains(&cell.key) {
                    continue;
                }
                if !registered
                    .iter()
                    .any(|&(reg_type, prop_key)| prop_key == cell.key && reg_type == type_token)
                {
                    continue;
                }
                match store.decode_property_value(cell.type_tag, cell.value_inline) {
                    Ok(value) => values.push((cell.key, value)),
                    Err(_) => {
                        Self::note_rebuild_gap(index);
                        return;
                    }
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            if index.has_vector_rel(type_token, *prop_key) {
                index.insert_vector_rel_value(type_token, *prop_key, value, id);
            }
        }
    }

    /// (Re)captures node `id`'s current value into each `registered` `(label_token, prop_key)` bitmap
    /// index it matches (`rmp` task #328). The bitmap analogue of [`index_one_node`](Self::index_one_node):
    /// the same single per-node path the full rebuild drives, so a recovered store rebuilds the
    /// low-cardinality bitmaps store-consistently. Each registered column the node carries gets the
    /// node's bit set under its value; a node carrying neither the label nor the property contributes
    /// nothing. Store and index are borrowed in **separate, non-overlapping** scopes (the borrow
    /// discipline of this file).
    ///
    /// # This refill produces a candidate SUPERSET, not exact membership
    ///
    /// The write path maintains a bitmap membership-EXACT (remove-then-reinsert, `rmp` #453) and the
    /// abort re-derive ([`rederive_node_bitmap`](Self::rederive_node_bitmap)) restores that exactness
    /// after a rollback. A *refill* cannot, and must not try: it has no reader and therefore no
    /// snapshot, so it indexes every property version rather than collapsing newest-wins (`rmp` #766)
    /// and gates membership on the live-OR-retained label superset rather than the raw live word
    /// (`rmp` #904). Both widenings exist for the same reason — a bitmap is a candidate SOURCE, so an
    /// extra membership is a false positive its consumer's re-check drops, while a node it wrongly
    /// OMITS is a committed row no re-check can ever resurrect.
    fn index_one_node_bitmap(
        store: &SharedRef<RecordStore<D, S>>,
        index: &SharedCell<IndexSet>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // Skip a slot that is not in use (`rmp` #453, F-IDX-3): the rebuild/declare callers only pass
        // ids from the in-use scan, but the abort re-derive (`rederive_node_bitmap`) may pass a node
        // whose CREATE was just rolled back — a header-only create-undo (#220) clears the slot's in-use
        // bit but PRESERVES its body, so `node_labels`/`superset_scan_node_property_values` below
        // would still decode residual labels/values and wrongly RE-INSERT a phantom. Guarding on
        // `in_use` keeps a reverted-create node out of every bitmap (correct: it no longer exists),
        // and is a defensive
        // no-op for the rebuild/declare callers (their nodes are always in use).
        match store.borrow().node(id) {
            Ok(node) if node.mvcc.in_use() => {}
            _ => return, // not in use, or a read fault: contribute nothing (the bitmap stays cleared).
        }
        // `rmp` task #904: the membership gate is the LIVE-OR-RETAINED label superset, never the raw
        // live word — see `RecordStore::node_label_superset` for why a refill must not read the word an
        // uncommitted `REMOVE n:L` is sitting on.
        let label_tokens = match store.borrow_mut().node_label_superset(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The node's property values, keeping only the keys a registered bitmap index covers for one of
        // this node's labels. Every version in the chain is indexed, with no newest-wins collapse
        // (`rmp` task #766): a value-bitmap is a candidate set re-checked against the store, so an extra
        // membership is a false positive the re-check drops, while a collapsed-away committed value is a
        // silently lost row. A node legitimately appears in several value-bitmaps of the same key while
        // more than one of its versions is live.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().superset_scan_node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                // No dedup by key: every version of a used key is indexed (`rmp` task #766).
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_bitmap(lt, *prop_key) {
                    index.insert_bitmap_value(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// Begins a transaction at `isolation`, returning its [`TxnId`].
    ///
    /// Its read snapshot is the store's latest commit ([`RecordStore::snapshot_ts`], `04 §5.2`), so
    /// it sees exactly what has committed so far; it is registered with the SSI tracker so its
    /// conflicts are tracked from this begin timestamp.
    pub fn begin(&self, isolation: IsolationLevel) -> TxnId {
        self.begin_inner(isolation, None)
    }

    /// Begins a transaction at `isolation`, stamping it with the **monotonic**-clock reading
    /// `begin_nanos` (nanoseconds, `rmp` #395) so the maximum-transaction-age sweep
    /// ([`aged_transactions`](Self::aged_transactions), `rmp` #477) can reap it once its lifetime
    /// exceeds the configured cap.
    ///
    /// The server's open path uses this; pass a reading from the **same** monotonic clock later handed
    /// to [`aged_transactions`](Self::aged_transactions), so an NTP step on the wall clock can neither
    /// expire a fresh transaction nor perpetually reprieve a stale one. Otherwise identical to
    /// [`begin`](Self::begin) (which leaves the transaction age-untracked, hence never reaped — the TCK
    /// / unit-test path).
    pub fn begin_at(&self, isolation: IsolationLevel, begin_nanos: u64) -> TxnId {
        self.begin_inner(isolation, Some(begin_nanos))
    }

    /// Shared body of [`begin`](Self::begin) / [`begin_at`](Self::begin_at): mints the id, snapshots
    /// the store's latest commit, registers SSI tracking, and inserts the active entry with its
    /// (optional) monotonic begin reading.
    fn begin_inner(&self, isolation: IsolationLevel, begin_nanos: Option<u64>) -> TxnId {
        let txn = self.mint_txn();
        // ONE snapshot read, taken by the store as it registers the transaction (`rmp` #1056). It used
        // to be two — `snapshot_ts()` here and `begin(txn)` on the next line — and under
        // `D-multi-writer` two reads are two instants: a commit landing between them gave the
        // coordinator and the store different start timestamps for the same transaction, and the
        // write-write check measures a committed chain head against the store's one.
        let begin_ts = self.store.borrow_mut().begin(txn);
        self.ssi.borrow_mut().register(txn, begin_ts);
        self.with_active(|a| {
            a.insert(
                txn,
                ActiveTxn {
                    snapshot: Snapshot::new(txn, begin_ts),
                    isolation,
                    begin_nanos,
                },
            )
        });
        txn
    }

    /// Begins a SERIALIZABLE transaction (the default level).
    pub fn begin_serializable(&self) -> TxnId {
        self.begin(IsolationLevel::Serializable)
    }

    /// Declares a node-property index on `(label, property)`, **durably records it** in the store's
    /// index catalog, and populates it from the current graph (`rmp` tasks #48 / #90).
    ///
    /// The label and property-key tokens are interned **durably** and the `(label_token, prop_key)`
    /// index is recorded in the durable index catalog (`rmp` task #90) — both in one committed
    /// transaction, so the *registration* survives a crash. Before `rmp` task #90 only the tokens were
    /// durable and the registered-index set lived only in the in-memory [`IndexSet`], so after a crash
    /// and reopen the index was silently lost; persisting the catalog entry fixes that. The index is
    /// then registered in the shared [`IndexSet`] and rebuilt so every existing node is indexed, and
    /// subsequent writes maintain it incrementally via the statement seam.
    ///
    /// Population is **synchronous** in this task (the non-blocking incremental build is `rmp`
    /// task #91), so the durable end-state of a successful create is [`IndexState::Online`]: the
    /// catalog entry is written `Online` in the same committed transaction as the tokens, and the
    /// in-memory index is registered `Online`. The index *data* itself is in-memory and candidate-only
    /// (never committed); only the token interning and the catalog entry need durability.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, or the
    /// committing transaction fails.
    pub fn create_node_property_index(&self, label: &str, property: &str) -> Result<()>
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        // Intern the label + prop-key tokens and record the durable catalog entry in one dedicated
        // transaction so the schema change (tokens + registration) survives a crash atomically, even
        // if no node yet uses them.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            // Record the index in the durable catalog at `Online` (population is synchronous here, so a
            // successful create ends `Online`). This becomes durable at the commit below, alongside the
            // tokens; a crash mid-create recovers to the last committed catalog (no entry), and the
            // failed create leaves no orphan registration.
            store.set_node_property_index(txn, label_token, prop_key, IndexState::Online);
            // Record a deterministic auto-name (`rmp` task #624) so this index is named end-to-end (it
            // shows up in `SHOW INDEXES` with a name and is droppable by name). Idempotent: recomputing
            // the auto-name of an index that already carries it is not a collision, so re-declaring the
            // same `(label, property)` keeps the same name.
            let name = Self::unique_auto_index_name(store, label, property, label_token, prop_key);
            store.set_node_property_index_name(txn, name, label_token, prop_key);
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing rows are
        // indexed. The durable catalog and the in-memory set now agree.
        self.index.borrow_mut().register_node_property_with_state(
            label_token,
            prop_key,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        // The index is Online and populated: seed its selectivity histogram so it is born with real
        // statistics (`rmp` task #572). Best-effort — never fails an otherwise-successful DDL.
        self.seed_index_histogram(label_token, prop_key);
        Ok(())
    }

    /// Declares a **relationship-property index** named `name` (or an auto-generated name) over
    /// `(rel_type, property)`, durably records it, and **synchronously builds** it from the existing
    /// relationships (`rmp` task #646) — the relationship analogue of
    /// [`create_node_property_index`](Self::create_node_property_index), plus the named / `IF NOT EXISTS`
    /// surface. Because the build is synchronous, a successful create ends [`IndexState::Online`].
    ///
    /// Returns whether an index was **actually created** (`true`) or the call was an idempotent
    /// `IF NOT EXISTS` no-op (`false`) — the executor turns `false` into a `0` `indexes-added` counter
    /// (Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent index on `(rel_type, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, or committing fails. On any
    ///   error the index is left undeclared.
    pub fn create_rel_property_index_named(
        &self,
        name: Option<&str>,
        rel_type: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index).
        let equivalent_exists = {
            let store = self.store.borrow();
            matches!(
                (
                    store.token_id(Namespace::RelType, rel_type),
                    store.token_id(Namespace::PropKey, property),
                ),
                (Some(tt), Some(pk)) if store.rel_property_index_state(tt, pk).is_some()
            )
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(equivalent_rel_index_exists(rel_type, property))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3
        //    (it needs the interned tokens for its deterministic collision suffix).
        if let Some(n) = name
            && Self::name_in_use(self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) + its name, in one
        //    committed transaction — so the schema change (tokens + registration) survives a crash
        //    atomically even if no relationship yet uses them.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (type_token, prop_key) = {
            let store = self.store.borrow_mut();
            let type_token = match store.intern_token(Namespace::RelType, rel_type) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_rel_index_name(
                    store, rel_type, property, type_token, prop_key,
                ),
            };
            store.set_rel_property_index(txn, type_token, prop_key, IndexState::Online);
            store.set_rel_property_index_name(txn, effective_name, type_token, prop_key);
            (type_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing relationships
        // are indexed. The durable catalog and the in-memory set now agree.
        self.index.borrow_mut().register_rel_property_with_state(
            type_token,
            prop_key,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(true)
    }

    /// Drops the relationship-property index covering `(rel_type, property)` (`rmp` task #646), the
    /// by-**target** `DROP INDEX FOR ()-[r:T]-() ON (r.p)` surface. Idempotent: a no-op success on a
    /// missing target. Removes the durable catalog + name entries in one committed transaction and
    /// unregisters the index from the in-memory [`IndexSet`].
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_rel_property_index(&self, rel_type: &str, property: &str) -> Result<bool> {
        let tokens = {
            let store = self.store.borrow();
            match (
                store.token_id(Namespace::RelType, rel_type),
                store.token_id(Namespace::PropKey, property),
            ) {
                (Some(type_token), Some(prop_key))
                    if store
                        .rel_property_index_state(type_token, prop_key)
                        .is_some() =>
                {
                    Some((type_token, prop_key))
                }
                _ => None,
            }
        };
        let Some((type_token, prop_key)) = tokens else {
            return Ok(false); // no such index → clean no-op, nothing removed.
        };

        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        {
            let store = self.store.borrow_mut();
            store.remove_rel_property_index(txn, type_token, prop_key);
            store.remove_rel_property_index_name_for(txn, type_token, prop_key);
        }
        self.store.borrow_mut().commit(txn)?;

        self.index
            .borrow_mut()
            .unregister_rel_property(type_token, prop_key);
        Ok(true)
    }

    /// Drops the relationship-property index named `name` (`rmp` task #646), the `DROP INDEX <name>`
    /// surface: resolves the name to its covered `(rel_type, property)`, removes the durable catalog +
    /// name entries in one committed transaction, and unregisters it from the in-memory [`IndexSet`].
    ///
    /// `if_exists` controls the missing-name case: `true` makes a never-declared name a clean no-op
    /// success; `false` returns `Neo.ClientError.Schema.IndexDropFailed`.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` (no `IF EXISTS`) when no index of that name exists;
    /// - a storage error if the committing transaction fails.
    pub fn drop_rel_property_index_by_name(&self, name: &str, if_exists: bool) -> Result<bool> {
        let target = self.store.borrow().rel_property_index_name(name);
        let Some((type_token, prop_key)) = target else {
            return if if_exists {
                Ok(false)
            } else {
                Err(index_drop_not_found(name))
            };
        };

        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        {
            let store = self.store.borrow_mut();
            store.remove_rel_property_index(txn, type_token, prop_key);
            store.remove_rel_property_index_name(txn, name);
        }
        self.store.borrow_mut().commit(txn)?;

        self.index
            .borrow_mut()
            .unregister_rel_property(type_token, prop_key);
        Ok(true)
    }

    /// Drops the index named `name` — resolving it against **every** index catalog so the unified
    /// Neo4j `DROP INDEX <name>` form (which does not spell the index kind) drops an index of any kind:
    /// node-property, relationship-property (`rmp` task #646), composite (`rmp` task #657), full-text
    /// and spatial/point (`rmp` task #661). Index names are globally unique across all catalogs, so at
    /// most one matches.
    ///
    /// `if_exists` controls the missing-name case: `true` makes a never-declared name a clean no-op
    /// success; `false` returns `Neo.ClientError.Schema.IndexDropFailed`.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` (no `IF EXISTS`) when no index of that name exists;
    /// - a storage error if the committing transaction fails.
    pub fn drop_property_index_by_name(&self, name: &str, if_exists: bool) -> Result<bool> {
        // A node-property index of that name? (Its resolver already handles the missing case, but we
        // gate here so a rel index of the same-shaped name is not shadowed by the node resolver's
        // "not found" — names are globally unique, so only one catalog can hold it.)
        if self.store.borrow().node_property_index_name(name).is_some() {
            return self.drop_node_property_index_by_name(name, if_exists);
        }
        // A relationship-property index of that name?
        if self.store.borrow().rel_property_index_name(name).is_some() {
            return self.drop_rel_property_index_by_name(name, if_exists);
        }
        // A standalone composite (multi-property) index of that name (`rmp` task #657)?
        let composite = self.store.borrow().composite_index(name);
        if let Some(entry) = composite {
            self.remove_composite_index_committed(name, entry.label_token, &entry.property_tokens)?;
            return Ok(true);
        }
        // A standalone composite relationship index of that name (`rmp` task #666)?
        let rel_composite = self.store.borrow().rel_composite_index(name);
        if let Some(entry) = rel_composite {
            self.remove_rel_composite_index_committed(
                name,
                entry.type_token,
                &entry.property_tokens,
            )?;
            return Ok(true);
        }
        // A full-text index of that name (`rmp` task #661)? The name is known-present here, so the
        // delegate removes it and returns `Ok(true)`.
        if self.store.borrow().fulltext_index(name).is_some() {
            return self.drop_fulltext_index(name, if_exists);
        }
        // A spatial (point) index of that name (`rmp` task #661)?
        if self.store.borrow().spatial_index(name).is_some() {
            return self.drop_point_index(name, if_exists);
        }
        // A text (trigram) index of that name (`rmp` task #662)?
        if self.store.borrow().text_index(name).is_some() {
            return self.drop_text_index(name, if_exists);
        }
        // A vector (HNSW) index of that name (`rmp` task #671)?
        if self.store.borrow().vector_index(name).is_some() {
            return self.drop_vector_index(name, if_exists);
        }
        // No catalog holds the name: honour `IF EXISTS`.
        if if_exists {
            Ok(false)
        } else {
            Err(index_drop_not_found(name))
        }
    }

    /// Drops the **standalone composite** index over `(label, properties)` — the by-target
    /// `DROP INDEX FOR (n:L) ON (n.a, n.b)` shape (`rmp` task #657). Resolves the covered composite by
    /// its label + ordered property tuple; a missing target is a clean no-op success. Returns whether an
    /// index was actually removed.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_node_composite_index(&self, label: &str, properties: &[String]) -> Result<bool> {
        let resolved = {
            let store = self.store.borrow();
            match Self::resolve_property_tokens(store, label, properties) {
                Some((label_token, property_tokens)) => store
                    .composite_index_name_for(label_token, &property_tokens)
                    .map(|name| (name.to_owned(), label_token, property_tokens)),
                None => None,
            }
        };
        let Some((name, label_token, property_tokens)) = resolved else {
            return Ok(false); // no such composite index → clean no-op.
        };
        self.remove_composite_index_committed(&name, label_token, &property_tokens)?;
        Ok(true)
    }

    /// Removes the durable composite index catalog entry named `name` in one committed transaction and
    /// unregisters its in-memory backing tree — **unless** a node-key constraint over the *same*
    /// `(label, tuple)` still needs it (`rmp` task #657). A standalone composite index and a node-key
    /// constraint over the same tuple share one in-memory tree (keyed by target, not name), so dropping
    /// the index must not tear the tree out from under a still-live constraint.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    fn remove_composite_index_committed(
        &self,
        name: &str,
        label_token: u32,
        property_tokens: &[u32],
    ) -> Result<()> {
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_composite_index(txn, name);
        self.store.borrow_mut().commit(txn)?;

        // Keep the backing tree iff a node-key constraint over the same tuple still shares it.
        let still_backs_node_key = self
            .index
            .borrow()
            .constraints_for_label(label_token)
            .iter()
            .any(|rule| {
                rule.kind == ConstraintKind::NodeKey && rule.property_tokens == property_tokens
            });
        if !still_backs_node_key {
            self.index
                .borrow_mut()
                .unregister_composite(label_token, property_tokens);
        }
        Ok(())
    }

    /// Lists every declared standalone composite index as `(name, label, properties, state)`
    /// (`rmp` task #657), for a `SHOW INDEXES` surface. Reads the durable catalog and resolves the
    /// tokens back to names; an entry whose tokens have no resolvable name (a defensively-skipped
    /// impossibility for a live token) is omitted. Ordered by the catalog's ascending name.
    #[must_use]
    pub fn list_composite_indexes(&self) -> Vec<(String, String, Vec<String>, IndexState)> {
        let store = self.store.borrow();
        store
            .composite_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                // The EFFECTIVE state (`rmp` task #733): a composite carries no in-memory state, so its
                // *registration* is its gate — a fail-closed unregisters it, and it is then unusable.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .has_composite(entry.label_token, &entry.property_tokens)
                        .then_some(IndexState::Online),
                );
                Some((name, label.to_owned(), properties, state))
            })
            .collect()
    }

    /// Drops the **standalone composite relationship** index over `(rel_type, properties)` — the
    /// by-target `DROP INDEX FOR ()-[r:T]-() ON (r.a, r.b)` shape (`rmp` task #666). Resolves the covered
    /// composite by its relationship type + ordered property tuple; a missing target is a clean no-op
    /// success. Returns whether an index was actually removed.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_rel_composite_index(&self, rel_type: &str, properties: &[String]) -> Result<bool> {
        let resolved = {
            let store = self.store.borrow();
            match Self::resolve_rel_property_tokens(store, rel_type, properties) {
                Some((type_token, property_tokens)) => store
                    .rel_composite_index_name_for(type_token, &property_tokens)
                    .map(|name| (name.to_owned(), type_token, property_tokens)),
                None => None,
            }
        };
        let Some((name, type_token, property_tokens)) = resolved else {
            return Ok(false); // no such composite relationship index → clean no-op.
        };
        self.remove_rel_composite_index_committed(&name, type_token, &property_tokens)?;
        Ok(true)
    }

    /// Removes the durable composite relationship index catalog entry named `name` in one committed
    /// transaction and unregisters its in-memory backing tree (`rmp` task #666). Unlike the node
    /// composite (which may share its tree with a node-key constraint), a composite relationship index
    /// backs no constraint (a relationship-key constraint stays scan-based), so its tree is always
    /// unregistered.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    fn remove_rel_composite_index_committed(
        &self,
        name: &str,
        type_token: u32,
        property_tokens: &[u32],
    ) -> Result<()> {
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store
            .borrow_mut()
            .remove_rel_composite_index(txn, name);
        self.store.borrow_mut().commit(txn)?;
        self.index
            .borrow_mut()
            .unregister_rel_composite(type_token, property_tokens);
        Ok(())
    }

    /// Lists every declared standalone composite relationship index as `(name, rel_type, properties,
    /// state)` (`rmp` task #666), for a `SHOW INDEXES` surface — the relationship analogue of
    /// [`list_composite_indexes`](Self::list_composite_indexes). An entry whose tokens have no resolvable
    /// name is omitted. Ordered by the catalog's ascending name.
    #[must_use]
    pub fn list_rel_composite_indexes(&self) -> Vec<(String, String, Vec<String>, IndexState)> {
        let store = self.store.borrow();
        store
            .rel_composite_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let rel_type = store.token_name(Namespace::RelType, entry.type_token)?;
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                // The EFFECTIVE state (`rmp` task #733) — registration is the gate, as for the node
                // composite above.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .has_rel_composite(entry.type_token, &entry.property_tokens)
                        .then_some(IndexState::Online),
                );
                Some((name, rel_type.to_owned(), properties, state))
            })
            .collect()
    }

    /// Lists every declared relationship-property index as `(name, rel_type, property, state)`
    /// (`rmp` task #646), for a `SHOW INDEXES` surface. Reads the durable catalog and resolves tokens
    /// back to names; the index **name** is the durable name if recorded, else the deterministic
    /// [`auto_rel_index_name`] fallback. An index whose tokens have no resolvable name is omitted.
    #[must_use]
    pub fn list_rel_property_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .rel_property_indexes()
            .into_iter()
            .filter_map(|(type_token, prop_key, state)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    state,
                    self.index.borrow().rel_property_state(type_token, prop_key),
                );
                let rel_type = store.token_name(Namespace::RelType, type_token)?;
                let property = store.token_name(Namespace::PropKey, prop_key)?;
                let name = store
                    .rel_property_index_name_for(type_token, prop_key)
                    .unwrap_or_else(|| auto_rel_index_name(&rel_type, &property));
                Some((name, rel_type.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Declares that the **complementary columnar value cache** (`rmp` tasks #329 / #330) should
    /// cover `(label, property)`, and **captures the column now** from the current graph.
    ///
    /// This is opt-in per `(label, property)`, exactly like declaring a node-property index — a caller
    /// (a server admin surface, the analytical examples/benches) declares the columns its analytical
    /// workload scans. Unlike a node-property index, **nothing here is durable**: the cache is a
    /// derived, in-memory, rebuilt-on-open accelerator (it has no on-disk / ACID / recovery surface),
    /// so a re-opened coordinator that wants the acceleration simply re-declares. The label and
    /// property-key tokens are interned (so a brand-new label/property resolves to a stable token) in
    /// one tiny committed transaction — that token interning is the *only* durable effect, identical
    /// to how any token is minted, and it carries no columnar data.
    ///
    /// After this returns, an analytical scan `MATCH (n:Label) RETURN agg(n.property)` over a
    /// statement seam reads the column from the cache (re-validated per node) instead of decoding each
    /// node's property chain. The result is **identical** to the row path — see
    /// [`RecordStoreGraph::columnar_label_property_scan`](crate::record_graph::RecordStoreGraph).
    ///
    /// # Errors
    /// Returns a storage error if interning either token (or its committing transaction) fails.
    pub fn declare_columnar_cache(&self, label: &str, property: &str) -> Result<()> {
        // Intern the tokens in one committed transaction (the only durable effect — no columnar data
        // is persisted). Mirrors the token-minting prologue of `create_node_property_index`.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Declare the column and capture it now from the current graph.
        self.columns.borrow_mut().declare(label_token, prop_key);
        Self::rebuild_columns(&self.store, &self.columns);
        Ok(())
    }

    /// Declares a **low-cardinality Roaring-bitmap index** on `(label, property)` (`rmp` task #328),
    /// the complementary index for boolean / enum-like / status columns: ~100× smaller postings than
    /// the B+-tree and microsecond multi-predicate AND via bitmap intersection (see
    /// [`bitmap_conjunction`](Self::bitmap_conjunction)). Like the columnar cache this is an **opt-in,
    /// derived, in-memory** structure — nothing here is durable except the token interning (the only
    /// durable effect, identical to any token mint); a re-opened coordinator re-declares. The column is
    /// captured now and kept **membership-exact** by the per-write re-index, so its seek result is a
    /// correct candidate set (the caller still re-checks MVCC visibility, exactly as for every index).
    ///
    /// Intended for **low-cardinality** columns; on a high-cardinality column a bitmap holds one id per
    /// value and the B+-tree (which also serves ranges) is the right structure — the declaration is the
    /// operator's assertion that the column is low-cardinality.
    ///
    /// # Cardinality guard (`rmp` task #453, F-IDX-5)
    ///
    /// The build is bounded by an **exact runtime distinct-value cap**
    /// ([`graphus_index::bitmap::MAX_DISTINCT_VALUES`]): as the store is scanned, the moment the column's
    /// live distinct-value count exceeds the cap the half-built bitmap is **torn down** (the column is
    /// unregistered) and the declaration is **refused** with a clear error, instead of letting one
    /// `RoaringTreemap`-per-value structure grow unbounded on a near-unique column (the OOM footgun the
    /// header doc warns about). The check is against the true built cardinality, so it needs no
    /// pre-existing cost histogram and cannot be fooled by an estimate.
    ///
    /// # Errors
    /// - A storage error if interning either token (or its committing transaction) fails.
    /// - [`GraphusError::Runtime`] if the column's distinct-value count exceeds
    ///   [`graphus_index::bitmap::MAX_DISTINCT_VALUES`] — the column is too high-cardinality for a
    ///   bitmap index (use the B+-tree node-property index instead).
    pub fn declare_bitmap_index(&self, label: &str, property: &str) -> Result<()> {
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the column and capture it now from the current graph (membership-exact).
        self.index
            .borrow_mut()
            .register_bitmap(label_token, prop_key);
        let registered = [(label_token, prop_key)];
        self.index.borrow_mut().clear_rebuild_gap();
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A scan fault used to `return Ok(())` here — reporting SUCCESS while leaving an EMPTY bitmap
            // registered (`rmp` task #733). A bitmap is a **membership-exact candidate source**, not a
            // hint: an empty one answers every seek with zero rows. Unregister it (it carries no
            // `IndexState` to demote, so registration IS its gate) and surface the fault.
            Err(e) => {
                self.index
                    .borrow_mut()
                    .unregister_bitmap(label_token, prop_key);
                return Err(e);
            }
        };
        // Build the bitmap, enforcing the distinct-value cap as we go (`rmp` #453, F-IDX-5). Checking
        // after each node short-circuits a near-unique column before its bitmap blows up, bounding the
        // transient memory too. On breach: unregister the (now-torn-down) column and refuse.
        for id in node_ids {
            Self::index_one_node_bitmap(&self.store, &self.index, id, &registered);
            if self
                .index
                .borrow()
                .bitmap_distinct(label_token, prop_key)
                .is_some_and(|d| d > graphus_index::bitmap::MAX_DISTINCT_VALUES)
            {
                self.index
                    .borrow_mut()
                    .unregister_bitmap(label_token, prop_key);
                return Err(GraphusError::Runtime(format!(
                    "cannot create a bitmap index on `{label}.{property}`: the column has more than {} \
                     distinct values (too high-cardinality for a bitmap index — use a node-property \
                     index instead)",
                    graphus_index::bitmap::MAX_DISTINCT_VALUES
                )));
            }
        }
        // A node the capture could not read is missing from the bitmap for good (`rmp` task #733), and a
        // bitmap is membership-exact — a seek against it would silently drop that node's rows. Unregister
        // and surface the fault rather than report success over a holed candidate source. (This also
        // clears the flag, which the old code left dirty for the next build to trip over.)
        if self.index.borrow().rebuild_gap() {
            let mut idx = self.index.borrow_mut();
            idx.clear_rebuild_gap();
            idx.unregister_bitmap(label_token, prop_key);
            drop(idx);
            return Err(GraphusError::Storage(format!(
                "cannot create a bitmap index on `{label}.{property}`: the store scan skipped at \
                 least one node"
            )));
        }
        Ok(())
    }

    /// Candidate node ids for `label` whose `property` equals `value`, via the declared bitmap index
    /// (`rmp` #328); `None` if no bitmap index is declared for the column. Test/diagnostic surface for
    /// the single-predicate bitmap seek (the caller re-checks visibility + the exact predicate).
    #[must_use]
    pub fn bitmap_seek_eq(&self, label: &str, property: &str, value: &Value) -> Option<Vec<u64>> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        let prop_key = store.token_id(Namespace::PropKey, property)?;
        self.index
            .borrow()
            .seek_bitmap_eq(label_token, prop_key, value)
    }

    /// Candidate node ids for `label` satisfying the conjunction of `(property, value)` equalities, via
    /// **bitmap intersection** (`rmp` #328 multi-predicate AND fast path); `None` unless every column
    /// has a declared bitmap index. The caller re-checks MVCC visibility + the exact predicates.
    #[must_use]
    pub fn bitmap_conjunction(
        &self,
        label: &str,
        predicates: &[(&str, &Value)],
    ) -> Option<Vec<u64>> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        // Resolve each predicate's prop-key token; a never-interned property has no index ⇒ decline.
        let mut resolved: Vec<(u32, &Value)> = Vec::with_capacity(predicates.len());
        for &(property, value) in predicates {
            let prop_key = store.token_id(Namespace::PropKey, property)?;
            resolved.push((prop_key, value));
        }
        self.index
            .borrow()
            .seek_bitmap_conjunction(label_token, &resolved)
    }

    /// The serialized byte footprint of the declared `(label, property)` bitmap index, or `None` if no
    /// bitmap index is declared. Used by the measurement harness to compare against the B+-tree
    /// postings size. (Diagnostics only.)
    #[must_use]
    pub fn bitmap_serialized_bytes(&self, label: &str, property: &str) -> Option<u64> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        let prop_key = store.token_id(Namespace::PropKey, property)?;
        self.index
            .borrow()
            .bitmap_serialized_bytes(label_token, prop_key)
    }

    // --------------------------------------------------------------------------------------------
    // Zone-map data-skipping sidecar (`rmp` task #331)
    // --------------------------------------------------------------------------------------------

    /// Declares a **zone-map data-skipping** sidecar on `(label, property)` (`rmp` task #331): a
    /// coarse per-zone `{min, max}` summary over the node-id space that lets a non-indexed predicate
    /// scan skip whole id zones whose range cannot match. Opt-in / derived / in-memory (only the token
    /// interning is durable), rebuilt from the current store now and maintained (widening) on every
    /// write. Best on a column clustered by node id (append-only timestamps / sequences); it degrades
    /// gracefully to a full scan on an unclustered column, and never changes a query's result.
    ///
    /// The summary **prunes only**; the rows are decided one layer up, by
    /// [`RecordStoreGraph::zone_scan_eq`](crate::record_graph::RecordStoreGraph::zone_scan_eq), which
    /// re-checks every candidate against the reader's snapshot (`rmp` #958). This method therefore
    /// never makes a visibility claim, and neither does anything else on [`TxnCoordinator`], which
    /// holds no statement snapshot.
    ///
    /// # Errors
    /// Returns a storage error if interning either token (or its committing transaction) fails.
    pub fn declare_zone_map(&self, label: &str, property: &str) -> Result<()> {
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        self.zones.borrow_mut().declare(label_token, prop_key);
        self.rebuild_zone_column(label_token, prop_key);
        Ok(())
    }

    /// Rebuilds one declared zone-map column from the current store: scans the slot-occupied nodes that
    /// carry the label in the live-OR-retained sense and captures `(id, value)` for **every version**
    /// of the property, then installs the per-zone summary. Reads without a snapshot, like the index
    /// rebuild.
    ///
    /// # A zone map PRUNES, so an omitted value is a lost row (`rmp` tasks #904, #958)
    ///
    /// This once claimed that "the scan's per-row re-check makes any later staleness harmless". That is
    /// true of a *widened* zone and false of a *narrowed* one: the per-row re-check only ever runs on
    /// the ids `candidate_ranges_eq` did not prune, so a value this rebuild leaves outside its zone's
    /// `[min, max]` — when it was that zone's only carrier of it — makes the whole id range disappear
    /// before any re-check happens. Nothing repairs a zone map afterwards (no rebuild on open, no
    /// rollback hook, only a later write to the same node), so the loss is permanent. The rebuild is
    /// therefore a **superset** on both axes, and fails closed on the third:
    ///
    /// * **labels** — the live-OR-retained union
    ///   [`RecordStore::node_label_superset`](graphus_storage::RecordStore::node_label_superset),
    ///   exactly as the index refills use (`rmp` #904), so a rebuild run while a writer holds an
    ///   uncommitted `REMOVE n:L` does not narrow a zone on a change that writer may roll back;
    /// * **values** — **every version** in the chain, not the newest (`rmp` #958). The newest version
    ///   may belong to an uncommitted writer whose rollback restores the older one, and even when it is
    ///   committed, a reader whose snapshot predates the overwrite resolves the *older* version
    ///   (`rmp` #50, newest-**visible**-wins). Summarising the newest alone narrows the zone on both
    ///   counts; the extra width only costs skipping, which the per-row re-check then recovers.
    /// * **read faults** — a node the scan cannot read is a node whose values are unknown, and an
    ///   unknown value cannot be excluded. The column is abandoned (it declines to a full scan until a
    ///   later complete rebuild) rather than summarised over the part of the store that happened to be
    ///   readable.
    fn rebuild_zone_column(&self, label_token: u32, prop_key: u32) {
        // Read-only store access (`rmp` #337 Slice 2): the rebuild scan only reads.
        let node_ids = match self.store.borrow().scan_node_ids() {
            Ok(ids) => ids,
            // The scan itself faulted: nothing was read, so nothing may be excluded (`rmp` #958).
            Err(_) => {
                self.zones
                    .borrow_mut()
                    .abandon_column(label_token, prop_key);
                return;
            }
        };
        let mut rows: Vec<(u64, Value)> = Vec::new();
        for id in node_ids {
            let (labels, chain) = {
                let store = self.store.borrow();
                // `rmp` task #904: the live-OR-retained superset, never the raw live word — see this
                // method's doc for why a narrowed zone is unrecoverable.
                let labels = match store.node_label_superset(id) {
                    Ok(l) => l,
                    Err(_) => {
                        self.zones
                            .borrow_mut()
                            .abandon_column(label_token, prop_key);
                        return;
                    }
                };
                let chain = match store.superset_scan_node_property_values(id) {
                    Ok(c) => c,
                    Err(_) => {
                        self.zones
                            .borrow_mut()
                            .abandon_column(label_token, prop_key);
                        return;
                    }
                };
                (labels, chain)
            };
            if !labels.contains(&label_token) {
                continue;
            }
            // EVERY version of the key widens the zone (`rmp` #958), not just the chain head.
            for (_pid, _k, value) in chain.iter().filter(|(_, k, _)| *k == prop_key) {
                rows.push((id, value.clone()));
            }
        }
        self.zones
            .borrow_mut()
            .rebuild_column(label_token, prop_key, rows);
    }

    /// Zones the most recent zone-map skip query pruned (`rmp` #331 measurement).
    ///
    /// The skip query itself is
    /// [`RecordStoreGraph::zone_scan_eq`](crate::record_graph::RecordStoreGraph::zone_scan_eq): the
    /// zone map is shared with the statement seam, and the counters it updates are read back here.
    #[must_use]
    pub fn zone_map_zones_skipped(&self) -> u64 {
        self.zones.borrow().zones_skipped()
    }

    /// Zones the most recent zone-map skip query kept / scanned.
    #[must_use]
    pub fn zone_map_zones_scanned(&self) -> u64 {
        self.zones.borrow().zones_scanned()
    }

    /// Re-captures **every declared** columnar column from the current store (`rmp` #329): the
    /// derived analogue of [`rebuild_index`](Self::rebuild_index) for the columnar cache. Each
    /// declared `(label_token, prop_key)` column is rebuilt by scanning the in-use nodes, capturing,
    /// for every node that currently carries the label and holds an index-stable value of the key, a
    /// [`ColumnRow`](crate::column_cache::ColumnRow) — the value plus the staleness witness the
    /// read-time re-check needs.
    ///
    /// Reads directly off the store with **no MVCC snapshot** (like `rebuild_index`): the cache is a
    /// candidate-class accelerator whose every entry is re-validated at read time, so capturing each
    /// node's *current* value is sufficient — a value that some future reader cannot see is harmless
    /// (the read-time re-check drops it, falling back to the row read). Store read faults on a single
    /// node skip that node best-effort (it degrades to the row path for that node, never a wrong row).
    /// The store and the cache are borrowed in separate scopes.
    ///
    /// # Polarity — CURRENT IMAGE, and why it may not be the candidate superset (`rmp` #967)
    ///
    /// This is one entry per node, keyed by node id, whose witness names a **`props.store` cell**. So
    /// it must read the live cells (`cells_ignoring_history`), not
    /// [`SupersetProperties::candidates`]: a candidate may come from the **undo store**, whose
    /// physical ids live in a different id space, so caching one would make the read-time witness
    /// probe read `props.store` at an undo-store id. It would also re-bake a **removed** value,
    /// because `candidates` drops the empty cell a `REMOVE` leaves behind and the key's first
    /// surviving candidate is then historical. Serving an older snapshot is not this structure's job —
    /// that reader's witness check fails and it falls back to the authoritative chain read.
    fn rebuild_columns(
        store: &SharedRef<RecordStore<D, S>>,
        columns: &SharedCell<crate::column_cache::ColumnCache>,
    ) {
        // The declared columns, captured before the scan so the cache is not borrowed across a store
        // borrow. Drop all captured data first (keeping declarations) so a rebuild starts clean.
        let declared: Vec<(u32, u32)> = columns.borrow().declared().to_vec();
        columns.borrow_mut().clear();
        if declared.is_empty() {
            return;
        }

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A whole-scan fault leaves every column empty; every reader then uses the row path.
            Err(_) => return,
        };

        // Accumulate each declared column's rows in node-id order (the scan order).
        let mut per_column: Vec<Vec<crate::column_cache::ColumnRow>> =
            declared.iter().map(|_| Vec::new()).collect();

        for id in node_ids {
            // Read the node's labels, first_prop chain head and live property CELLS once. The cells
            // are kept UNDECODED here: only the declared keys are decoded below, which narrows the
            // fault surface (an unreadable overflow chain of an undeclared property no longer costs
            // this node its whole row) and skips the overflow walks for keys no column caches.
            let (label_tokens, first_prop, cells): (Vec<u32>, u64, Vec<(u64, PropRecord)>) = {
                // Read-only store access (`rmp` #337 Slice 2): the column rebuild scan only reads.
                let store = store.borrow();
                let node = match store.node(id) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                // Tombstoned / not-in-use slots are skipped (the index rebuild skips them too via the
                // in-use scan; this guards a since-reclaimed slot defensively).
                if !node.mvcc.in_use() {
                    continue;
                }
                let labels = match store.node_labels(id) {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let cells = match store.superset_scan_node_properties(id) {
                    Ok(chain) => chain.cells_ignoring_history().to_vec(),
                    Err(_) => continue,
                };
                (labels, node.first_prop, cells)
            };

            // For each declared column the node matches, capture its current value of the key.
            for (ci, &(label_token, prop_key)) in declared.iter().enumerate() {
                if !label_tokens.contains(&label_token) {
                    continue;
                }
                // A healthy post-#967 store holds ONE cell per key, so the first match is the node's
                // current value; an EMPTY cell means the key was removed in place and the node
                // contributes no row (`D-property-removal`).
                let Some(&(pid, cell)) = cells
                    .iter()
                    .find(|(_, c)| c.key == prop_key && c.type_tag != TYPE_TAG_ABSENT)
                else {
                    continue;
                };
                let value = match store
                    .borrow()
                    .decode_property_value(cell.type_tag, cell.value_inline)
                {
                    Ok(v) => v,
                    Err(_) => continue, // undecodable: this node degrades to the row path
                };
                per_column[ci].push(crate::column_cache::ColumnRow {
                    node_id: id,
                    value,
                    witness: crate::column_cache::ColumnWitness {
                        prop_pid: pid,
                        node_first_prop: first_prop,
                        type_tag: cell.type_tag,
                        value_inline: cell.value_inline,
                        created_ts: cell.mvcc.created_ts,
                    },
                });
            }
        }

        // Install the captured columns (cache borrow only).
        let mut cache = columns.borrow_mut();
        for ((label_token, prop_key), rows) in declared.into_iter().zip(per_column) {
            cache.set_column(label_token, prop_key, rows);
        }
    }

    /// The number of cached rows for the columnar column `(label, property)`, or `None` when the pair
    /// is not a declared/captured column (`rmp` #329). A diagnostics / test accessor proving the
    /// column was actually captured (so a measurement is not vacuously over an empty cache).
    #[must_use]
    pub fn columnar_column_len(&self, label: &str, property: &str) -> Option<usize> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        let prop_key = store.token_id(Namespace::PropKey, property)?;
        self.columns.borrow().column_len(label_token, prop_key)
    }

    /// The number of times the columnar analytical read path served a cached column since this
    /// coordinator was built (`rmp` #330): a cheap monitor / test signal that the accelerator was
    /// actually engaged (a test asserts it incremented, so an equivalence check is not vacuously
    /// comparing the row path against itself).
    #[must_use]
    pub fn columnar_scan_hits(&self) -> u64 {
        self.columns.borrow().scan_hits()
    }

    /// The number of columnar scans that **re-used a column's memoized decode** instead of decoding it
    /// afresh (`rmp` task #375): a second scan of an un-mutated column hits this, proving the
    /// dictionary/integer decode (and the per-query lookup map) is paid once, not per query. A test
    /// asserts it increments on a repeat scan and stays put across a re-capture (new generation).
    #[must_use]
    pub fn columnar_decode_cache_hits(&self) -> u64 {
        self.columns.borrow().decode_cache_hits()
    }

    /// The cumulative count of values the columnar path served straight from the contiguous column
    /// (zero property-record decode) since this coordinator was built (`rmp` #329/#330) — the
    /// accelerator's payoff signal, exposed for measurement.
    #[must_use]
    pub fn columnar_value_hits(&self) -> u64 {
        self.columns.borrow().value_hits()
    }

    /// The cumulative count of values the columnar path read from the authoritative property chain (a
    /// stale / missing cache entry) since this coordinator was built (`rmp` #329/#330). On a fresh
    /// cache this stays `0`; the row path pays one such decode for every matched node, so the pair
    /// `(columnar_value_hits, columnar_fallback_reads)` is the measured decode reduction.
    #[must_use]
    pub fn columnar_fallback_reads(&self) -> u64 {
        self.columns.borrow().fallback_reads()
    }

    /// The number of times the **parallel** label-property aggregation tier (`rmp` task #352) projected
    /// a snapshot off this coordinator's columnar cache and folded it across cores. Distinct from
    /// [`columnar_scan_hits`](Self::columnar_scan_hits) (which the serial columnar scan also bumps): a
    /// test asserts this incremented to prove the parallel path was actually taken, so a
    /// parallel-vs-serial equivalence check is not vacuously comparing serial against itself.
    #[must_use]
    pub fn parallel_scan_hits(&self) -> u64 {
        self.columns.borrow().parallel_scan_hits()
    }

    /// Declares a node-property index on `(label, property)` and starts a **non-blocking** background
    /// build of it (`rmp` task #91): the catalog entry is recorded durably as [`IndexState::Populating`]
    /// and a pending build is enqueued, but **no node is scanned here** — the call returns promptly so
    /// the single-threaded engine stays responsive to other commands. The build is advanced in bounded
    /// chunks by [`advance_index_builds`](Self::advance_index_builds) and promoted to
    /// [`IndexState::Online`] only when every snapshot node has been indexed.
    ///
    /// In contrast, [`create_node_property_index`](Self::create_node_property_index) populates the
    /// index **synchronously** before returning (`Online` on success) — keep it for the
    /// startup/recovery path and any caller that can tolerate a blocking full-store scan; use *this*
    /// for a live `CREATE INDEX` over a populated store, where blocking the engine thread for the scan
    /// would stall every concurrent query.
    ///
    /// # Build snapshot and the no-missed-results guarantee
    ///
    /// At build start the current live node-id list is snapshotted ([`RecordStore::scan_node_ids`]).
    /// The build later indexes each snapshot node's *current* state. Concurrent writes between chunks
    /// are covered without any extra bookkeeping because the index is a **candidate set** and writes
    /// already maintain it (`RecordStoreGraph::reindex_node` inserts into *every* registered index in
    /// *any* state):
    ///
    /// - A node **deleted** before the scan reaches it → indexed as a stale candidate → harmless (the
    ///   seek's re-check drops the now-invisible version).
    /// - A node **created** after build start → not in the snapshot, but `reindex_node` inserts its
    ///   current label/value on the creating write → covered.
    /// - A value **changed** mid-build → `reindex_node` inserts the new value as a candidate; the
    ///   snapshot scan may also insert the old value; both are candidates and the re-check keeps only
    ///   the current one → covered.
    ///
    /// So at completion every node that should match is a candidate (zero missed results), and only
    /// harmless stale candidates may exist — exactly the contract the executor's re-check already
    /// assumes.
    ///
    /// While `Populating`, the planner withholds the index (it is absent from
    /// [`catalog`](Self::catalog)), so reads fall back to a label-scan + filter and observe correct
    /// results throughout the build.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, the committing
    /// transaction, or the initial snapshot scan fails. On any error the index is left undeclared.
    ///
    /// # Naming
    /// This positional form is the internal / test / bench entry point: it assigns a deterministic
    /// **auto-name** (`rmp` task #624) and is **idempotent** on the covered `(label, property)` — a
    /// re-declare is a clean no-op success. The named server surface (a Cypher `CREATE INDEX`) goes
    /// through [`begin_online_node_property_index_named`](Self::begin_online_node_property_index_named),
    /// which enforces global name uniqueness and Neo4j `IF NOT EXISTS` semantics.
    pub fn begin_online_node_property_index(&self, label: &str, property: &str) -> Result<()> {
        // `if_not_exists = true` preserves the historical idempotent-on-redeclare behaviour of this
        // positional API (a second declare of the same index is a no-op, never an error). The
        // created-vs-no-op flag is irrelevant to the positional callers, so it is discarded here.
        self.begin_online_node_property_index_named(None, label, property, true)
            .map(|_created| ())
    }

    /// Declares a **named** node-property index on `(label, property)` and starts a **non-blocking**
    /// background build of it, enforcing Neo4j-conformant schema semantics (`rmp` tasks #91, #624):
    ///
    /// - `name` is the requested server-unique name, or [`None`] to auto-generate a deterministic one
    ///   ([`auto_index_name`]);
    /// - the covered `(label, property)` must not already be indexed by an **equivalent** index, and
    ///   the resolved name must not already be used by **any** schema catalog (node-property, full-text,
    ///   spatial, constraint) — names are globally unique;
    /// - `if_not_exists` turns both "already exists" cases (equivalent index / name in use) into a
    ///   **no-op success** instead of an error, matching `CREATE INDEX … IF NOT EXISTS`.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing) — the executor turns `false` into a `0`
    /// `indexes-added` counter (`rmp` task #626 follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// The build snapshot / no-missed-results contract is identical to the positional
    /// [`begin_online_node_property_index`](Self::begin_online_node_property_index) (see its docs); this
    /// method only adds the naming + idempotency layer around it.
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent index on `(label, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the initial
    ///   snapshot scan fails. On any error the index is left undeclared.
    pub fn begin_online_node_property_index_named(
        &self,
        name: Option<&str>,
        label: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index).
        let equivalent_exists = {
            let store = self.store.borrow();
            matches!(
                (
                    store.token_id(Namespace::Label, label),
                    store.token_id(Namespace::PropKey, property),
                ),
                (Some(lt), Some(pk)) if store.node_property_index_state(lt, pk).is_some()
            )
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(equivalent_index_exists(label, property))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3
        //    (it needs the interned tokens for its deterministic collision suffix).
        if let Some(n) = name
            && Self::name_in_use(self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Populating`) + its name, in one
        //    committed transaction — so the schema change survives a crash atomically, and an interrupted
        //    build recovers `Populating` and is completed by the open-time rebuild.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_index_name(store, label, property, label_token, prop_key),
            };
            store.set_node_property_index(txn, label_token, prop_key, IndexState::Populating);
            store.set_node_property_index_name(txn, effective_name, label_token, prop_key);
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Populating` in the in-memory set so concurrent writes maintain it from
        // now on (the planner still withholds it until it is promoted `Online`).
        self.index.borrow_mut().register_node_property_with_state(
            label_token,
            prop_key,
            IndexState::Populating,
        );

        // Snapshot the current live node-id list and enqueue the pending build. The scan is the only
        // store walk here; the per-node indexing is deferred to `advance_index_builds`.
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        builds.pending_builds.push_back(PendingIndexBuild {
            label_token,
            prop_key,
            snapshot,
            cursor: 0,
            generation: self.index.borrow().wipe_generation(),
            stall: BUILD_STALL_BUDGET,
        });
        Ok(true) // the index was created.
    }

    /// Declares a node index over `(label, properties)` — a **single-property** RANGE index when
    /// `properties` has arity 1, or a **composite** (multi-property) RANGE index when arity ≥ 2
    /// (`rmp` task #657) — enforcing Neo4j-conformant schema semantics.
    ///
    /// This is the single server entry point behind `CREATE INDEX FOR (n:L) ON (n.a[, n.b, …])`:
    ///
    /// - **arity 1** delegates verbatim to
    ///   [`begin_online_node_property_index_named`](Self::begin_online_node_property_index_named), so the
    ///   single-property (non-blocking, `Populating` → `Online`) path is untouched — nothing regresses;
    /// - **arity ≥ 2** declares a **standalone** composite index — distinct from a node-key constraint's
    ///   backing composite (`rmp` task #100), it enforces **no uniqueness**. The label + property-key
    ///   tokens are interned **durably** and the named catalog entry is recorded as
    ///   [`IndexState::Online`] in one committed transaction (so the *registration* survives a crash),
    ///   then the index is registered in the in-memory [`IndexSet`] and **synchronously built** from the
    ///   current nodes. The synchronous build is crash-safe: the backing tree is ephemeral and rebuilt
    ///   from the durable catalog + store on open, so a crash mid-build recovers the `Online`
    ///   registration and repopulates it — recovery never observes a half-built index.
    ///
    /// The composite key **order is significant** (`(a, b)` differs from `(b, a)`). Returns whether the
    /// index was **actually created** (`true`) or the call was an idempotent no-op (`false`, an
    /// `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent composite index on `(label, ordered tuple)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build
    ///   scan fails. On any error the index is left undeclared.
    ///
    /// # Panics
    /// Panics if `properties` is empty (the parser guarantees at least one property; a composite has two
    /// or more).
    pub fn begin_online_node_composite_index_named(
        &self,
        name: Option<&str>,
        label: &str,
        properties: &[String],
        if_not_exists: bool,
    ) -> Result<bool> {
        assert!(
            !properties.is_empty(),
            "a node index covers at least one property"
        );
        // Arity 1: keep the single-property path (non-blocking build, no regression).
        if let [property] = properties {
            return self.begin_online_node_property_index_named(
                name,
                label,
                property,
                if_not_exists,
            );
        }

        // ---- Arity ≥ 2: a standalone composite index (`rmp` task #657) --------------------------------

        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index can
        //    cover this tuple, so no equivalent exists).
        let equivalent_exists = {
            let store = self.store.borrow();
            match Self::resolve_property_tokens(store, label, properties) {
                Some((label_token, property_tokens)) => store
                    .composite_index_name_for(label_token, &property_tokens)
                    .is_some(),
                None => false,
            }
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(equivalent_composite_index_exists(label, properties))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3.
        if let Some(n) = name
            && Self::name_in_use(self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) in one committed
        //    transaction — so the schema change survives a crash atomically.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, property_tokens, effective_name) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_composite_index_name(
                    store,
                    label,
                    properties,
                    label_token,
                    &property_tokens,
                ),
            };
            store.set_composite_index(
                txn,
                effective_name.clone(),
                CompositeIndexEntry {
                    label_token,
                    property_tokens: property_tokens.clone(),
                    state: IndexState::Online,
                },
            );
            (label_token, property_tokens, effective_name)
        };
        let _ = effective_name; // recorded durably above; the in-memory tree is keyed by target, not name.
        self.store.borrow_mut().commit(txn)?;

        // Register the composite in the in-memory set so concurrent writes maintain it from now on, then
        // synchronously index the existing nodes into its backing tree. The tree is ephemeral (rebuilt on
        // open from the durable catalog + store), so this synchronous fill is a pure in-memory build with
        // no durability surface — a crash before it finishes recovers the `Online` registration and the
        // open-time rebuild repopulates the tree store-consistently.
        self.index
            .borrow_mut()
            .register_composite(label_token, property_tokens.clone());
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                // The build could not start (`rmp` task #733). A composite index carries no
                // [`IndexState`] in the in-memory set — its consumers gate on *registration*
                // (`has_composite`) — so the only way to make it unusable is to **unregister** it.
                // Leaving it registered-and-empty would be far worse than slow: the node-key duplicate
                // check (`composite_seek_eq`) trusts it as an exact candidate source, so an empty tree
                // would report "no duplicate" for every tuple and let a NODE KEY constraint be violated.
                // Unregistered, both the planner's seek and the duplicate check fall back to the exact
                // label scan; the durable catalog is untouched, so any later successful `rebuild_index`
                // (or a reopen) re-registers and repopulates it.
                self.index
                    .borrow_mut()
                    .unregister_composite(label_token, &property_tokens);
                return Err(e);
            }
        };
        let registered = vec![(label_token, property_tokens.clone())];
        self.index.borrow_mut().clear_rebuild_gap();
        for id in node_ids {
            Self::index_one_node_composite(&self.store, &self.index, id, &registered);
        }
        // A node the fill could not read is missing from the composite tree for good (`rmp` task #733) —
        // and a node-key constraint trusts that tree as an EXACT candidate source, so a hole in it would
        // let a duplicate tuple through. Unregister (the tree has no state to demote), so the duplicate
        // check and the planner both fall back to the exact label scan, and surface the fault.
        if self.index.borrow().rebuild_gap() {
            let mut idx = self.index.borrow_mut();
            idx.clear_rebuild_gap();
            idx.unregister_composite(label_token, &property_tokens);
            drop(idx);
            return Err(GraphusError::Storage(
                "the composite index could not be built: the store scan skipped at least one node"
                    .to_owned(),
            ));
        }
        Ok(true) // the index was created.
    }

    /// Resolves `(label, properties)` to `(label_token, property_tokens)` by **token lookup** (never
    /// interning) (`rmp` task #657). Returns [`None`] if the label or **any** property key has no
    /// interned token — meaning no index can cover this tuple, so no equivalent index exists.
    fn resolve_property_tokens(
        store: &RecordStore<D, S>,
        label: &str,
        properties: &[String],
    ) -> Option<(u32, Vec<u32>)> {
        let label_token = store.token_id(Namespace::Label, label)?;
        let mut property_tokens = Vec::with_capacity(properties.len());
        for property in properties {
            property_tokens.push(store.token_id(Namespace::PropKey, property)?);
        }
        Some((label_token, property_tokens))
    }

    /// A globally-unique, deterministic auto-name for the composite index on `(label, properties)`
    /// (`rmp` task #657) — the composite analogue of
    /// [`unique_auto_index_name`](Self::unique_auto_index_name). The equivalence check in the caller has
    /// already guaranteed no composite index covers this exact target, so the base name can only collide
    /// with an *unrelated* schema rule; a deterministic token-suffixed form, then a numeric counter,
    /// resolves any residual collision so the returned name is free across **every** catalog.
    fn unique_auto_composite_index_name(
        store: &RecordStore<D, S>,
        label: &str,
        properties: &[String],
        label_token: u32,
        property_tokens: &[u32],
    ) -> String {
        let base = auto_composite_index_name(label, properties);
        if !Self::name_in_use(store, &base) {
            return base;
        }
        let mut suffixed = format!("{base}_{label_token}");
        for t in property_tokens {
            suffixed.push('_');
            suffixed.push_str(&t.to_string());
        }
        if !Self::name_in_use(store, &suffixed) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::name_in_use(store, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Declares a relationship index over `(rel_type, properties)` — a **single-property** RANGE index
    /// when `properties` has arity 1, or a **composite** (multi-property) RANGE index when arity ≥ 2
    /// (`rmp` task #666) — the relationship analogue of
    /// [`begin_online_node_composite_index_named`](Self::begin_online_node_composite_index_named).
    ///
    /// This is the single server entry point behind `CREATE INDEX FOR ()-[r:T]-() ON (r.a[, r.b, …])`:
    ///
    /// - **arity 1** delegates verbatim to
    ///   [`create_rel_property_index_named`](Self::create_rel_property_index_named), so the
    ///   single-property relationship path is untouched — nothing regresses;
    /// - **arity ≥ 2** declares a **standalone** composite relationship index (no uniqueness). The
    ///   relationship-type + property-key tokens are interned **durably** and the named catalog entry is
    ///   recorded [`IndexState::Online`] in one committed transaction (so the *registration* survives a
    ///   crash), then the index is registered in the in-memory [`IndexSet`] and **synchronously built**
    ///   from the current relationships. The synchronous build is crash-safe: the backing tree is
    ///   ephemeral and rebuilt from the durable catalog + store on open, so recovery never observes a
    ///   half-built index.
    ///
    /// The composite key **order is significant** (`(a, b)` differs from `(b, a)`). Returns whether the
    /// index was **actually created** (`true`) or the call was an idempotent no-op (`false`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent composite relationship index on `(rel_type, ordered tuple)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build
    ///   scan fails. On any error the index is left undeclared.
    ///
    /// # Panics
    /// Panics if `properties` is empty (the parser guarantees at least one property).
    pub fn begin_online_rel_composite_index_named(
        &self,
        name: Option<&str>,
        rel_type: &str,
        properties: &[String],
        if_not_exists: bool,
    ) -> Result<bool> {
        assert!(
            !properties.is_empty(),
            "a relationship index covers at least one property"
        );
        // Arity 1: keep the single-property relationship path (no regression).
        if let [property] = properties {
            return self.create_rel_property_index_named(name, rel_type, property, if_not_exists);
        }

        // ---- Arity ≥ 2: a standalone composite relationship index (`rmp` task #666) ------------------

        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index can
        //    cover this tuple, so no equivalent exists).
        let equivalent_exists = {
            let store = self.store.borrow();
            match Self::resolve_rel_property_tokens(store, rel_type, properties) {
                Some((type_token, property_tokens)) => store
                    .rel_composite_index_name_for(type_token, &property_tokens)
                    .is_some(),
                None => false,
            }
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(equivalent_rel_composite_index_exists(rel_type, properties))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3.
        if let Some(n) = name
            && Self::name_in_use(self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) in one committed
        //    transaction — so the schema change survives a crash atomically.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (type_token, property_tokens, effective_name) = {
            let store = self.store.borrow_mut();
            let type_token = match store.intern_token(Namespace::RelType, rel_type) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_rel_composite_index_name(
                    store,
                    rel_type,
                    properties,
                    type_token,
                    &property_tokens,
                ),
            };
            store.set_rel_composite_index(
                txn,
                effective_name.clone(),
                RelCompositeIndexEntry {
                    type_token,
                    property_tokens: property_tokens.clone(),
                    state: IndexState::Online,
                },
            );
            (type_token, property_tokens, effective_name)
        };
        let _ = effective_name; // recorded durably above; the in-memory tree is keyed by target, not name.
        self.store.borrow_mut().commit(txn)?;

        // Register the composite in the in-memory set so concurrent writes maintain it, then synchronously
        // index the existing relationships into its backing tree. The tree is ephemeral (rebuilt on open),
        // so this synchronous fill has no durability surface — a crash recovers the `Online` registration
        // and the open-time rebuild repopulates the tree store-consistently.
        self.index
            .borrow_mut()
            .register_rel_composite(type_token, property_tokens.clone());
        let rel_ids = match self.store.borrow().scan_rel_ids() {
            Ok(ids) => ids,
            Err(e) => {
                // The build could not start: unregister so the empty tree can never answer a seek
                // (`rmp` task #733) — the relationship twin of the node composite fail-closed above.
                self.index
                    .borrow_mut()
                    .unregister_rel_composite(type_token, &property_tokens);
                return Err(e);
            }
        };
        let registered = vec![(type_token, property_tokens.clone())];
        self.index.borrow_mut().clear_rebuild_gap();
        for id in rel_ids {
            Self::index_one_rel_composite(&self.store, &self.index, id, &registered);
        }
        // The relationship twin of the node composite guard (`rmp` task #733): unregister the holed tree
        // so every consumer falls back to the exact typed scan, and surface the fault.
        if self.index.borrow().rebuild_gap() {
            let mut idx = self.index.borrow_mut();
            idx.clear_rebuild_gap();
            idx.unregister_rel_composite(type_token, &property_tokens);
            drop(idx);
            return Err(GraphusError::Storage(
                "the composite relationship index could not be built: the store scan skipped at \
                 least one relationship"
                    .to_owned(),
            ));
        }
        Ok(true) // the index was created.
    }

    /// Resolves `(rel_type, properties)` to `(type_token, property_tokens)` by **token lookup** (never
    /// interning) (`rmp` task #666) — the relationship analogue of
    /// [`resolve_property_tokens`](Self::resolve_property_tokens). Returns [`None`] if the relationship
    /// type or **any** property key has no interned token — meaning no index can cover this tuple.
    fn resolve_rel_property_tokens(
        store: &RecordStore<D, S>,
        rel_type: &str,
        properties: &[String],
    ) -> Option<(u32, Vec<u32>)> {
        let type_token = store.token_id(Namespace::RelType, rel_type)?;
        let mut property_tokens = Vec::with_capacity(properties.len());
        for property in properties {
            property_tokens.push(store.token_id(Namespace::PropKey, property)?);
        }
        Some((type_token, property_tokens))
    }

    /// A globally-unique, deterministic auto-name for the composite relationship index on
    /// `(rel_type, properties)` (`rmp` task #666) — the relationship analogue of
    /// [`unique_auto_composite_index_name`](Self::unique_auto_composite_index_name).
    fn unique_auto_rel_composite_index_name(
        store: &RecordStore<D, S>,
        rel_type: &str,
        properties: &[String],
        type_token: u32,
        property_tokens: &[u32],
    ) -> String {
        let base = auto_rel_composite_index_name(rel_type, properties);
        if !Self::name_in_use(store, &base) {
            return base;
        }
        let mut suffixed = format!("{base}_{type_token}");
        for t in property_tokens {
            suffixed.push('_');
            suffixed.push_str(&t.to_string());
        }
        if !Self::name_in_use(store, &suffixed) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::name_in_use(store, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Declares a **full-text index** named `name` over `(label, properties)` analyzed with
    /// `analyzer`, **durably records it**, and starts a **non-blocking** background build of it
    /// (`rmp` task #72) — the full-text analogue of
    /// [`begin_online_node_property_index`](Self::begin_online_node_property_index).
    ///
    /// The label and property-key tokens are interned **durably** and the named catalog entry is
    /// recorded as [`IndexState::Populating`] — both in one committed transaction, so the
    /// *registration* survives a crash (an interrupted build recovers `Populating` and is completed by
    /// the open-time rebuild). The index is registered in the in-memory [`IndexSet`] so concurrent
    /// writes maintain it from now on, and a pending build is enqueued; **no node is scanned here**, so
    /// the engine stays responsive. The build is advanced in bounded chunks by
    /// [`advance_index_builds`](Self::advance_index_builds) and promoted to [`IndexState::Online`] only
    /// when every snapshot node has been indexed.
    ///
    /// Re-declaring an existing name **replaces** it (a fresh build over the new label/properties).
    ///
    /// # Errors
    /// Returns a storage error if `properties` is empty, interning any token, recording the catalog
    /// entry, the committing transaction, or the initial snapshot scan fails. On any error the index
    /// is left undeclared.
    pub fn create_fulltext_index(
        &self,
        name: &str,
        labels: &[String],
        properties: &[String],
        analyzer: Analyzer,
        if_not_exists: bool,
    ) -> Result<bool> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        if properties.is_empty() {
            return Err(GraphusError::Storage(
                "a full-text index must cover at least one property".to_owned(),
            ));
        }
        if labels.is_empty() {
            return Err(GraphusError::Storage(
                "a node full-text index must cover at least one label".to_owned(),
            ));
        }
        // `IF NOT EXISTS` (`rmp` #661): an equivalent index — the same `name` in the full-text catalog,
        // or the same covered `(entity, ordered label/type tuple, ordered property tuple)` under any
        // name — makes this an idempotent no-op (nothing added), mirroring the node-property path.
        if if_not_exists
            && self.fulltext_equivalent_exists(name, FulltextEntity::Node, labels, properties)
        {
            return Ok(false);
        }
        // Names are globally unique across every schema catalog (`rmp` task #624): reject a name already
        // used by a *different* catalog. Re-declaring within the full-text catalog keeps its historical
        // replace semantics (a name it already owns is not "used by another catalog").
        if Self::name_used_by_other_catalog(self.store.borrow(), name, NameCatalog::Fulltext) {
            return Err(index_name_in_use(name));
        }

        // Intern the label + property-key tokens and record the durable catalog entry `Populating`, in
        // one committed transaction (so the schema change survives a crash atomically).
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let entry = {
            let store = self.store.borrow_mut();
            let mut label_tokens = Vec::with_capacity(labels.len());
            for label in labels {
                match store.intern_token(Namespace::Label, label) {
                    Ok(t) => {
                        // De-duplicate a repeated label (`FOR (n:A|A)`) so the token set stays minimal.
                        if !label_tokens.contains(&t) {
                            label_tokens.push(t);
                        }
                    }
                    Err(e) => {
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let entry = FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: label_tokens,
                property_tokens,
                analyzer: analyzer.as_byte(),
                state: IndexState::Populating,
            };
            store.set_fulltext_index(txn, name.to_owned(), entry.clone());
            entry
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Populating` in the in-memory set so concurrent writes maintain it.
        self.index.borrow_mut().register_fulltext(
            name,
            entry.tokens,
            entry.property_tokens,
            analyzer,
            IndexState::Populating,
        );

        // Cancel any prior build of the same name — pending OR parked poisoned (`rmp` task #573) — then
        // enqueue this one. A parked build left behind would be resurrected later and race this one.
        self.cancel_fulltext_builds(name);
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        builds
            .pending_fulltext_builds
            .push_back(PendingFulltextBuild {
                name: name.to_owned(),
                snapshot,
                cursor: 0,
                generation: self.index.borrow().wipe_generation(),
                stall: BUILD_STALL_BUDGET,
                conflict_writers: Vec::new(),
            });
        Ok(true)
    }

    /// Declares a **relationship** full-text index named `name` over `types` (one or more relationship
    /// types) + `properties`, analyzed by `analyzer`, and **synchronously builds** it (`rmp` task #663)
    /// — the relationship analogue of [`create_fulltext_index`](Self::create_fulltext_index).
    ///
    /// Unlike the node full-text index (which builds non-blockingly), the relationship index is built
    /// **synchronously and recorded `Online`** in one committed transaction, then a full
    /// [`rebuild_index`](Self::rebuild_index) repopulates its rel-keyed inverted index from the store —
    /// exactly the pattern the relationship-property index (`rmp` #646) uses. `rebuild_index` also
    /// resets the shared full-text/spatial freshness marker to the store's high-water, so a reader whose
    /// snapshot predates the build declines to the correct scan path.
    ///
    /// # Errors
    /// Returns a storage error if `types` or `properties` is empty, interning any token, recording the
    /// catalog entry, or the committing transaction fails. On any error the index is left undeclared.
    pub fn create_fulltext_rel_index(
        &self,
        name: &str,
        types: &[String],
        properties: &[String],
        analyzer: Analyzer,
        if_not_exists: bool,
    ) -> Result<bool> {
        if properties.is_empty() {
            return Err(GraphusError::Storage(
                "a full-text index must cover at least one property".to_owned(),
            ));
        }
        if types.is_empty() {
            return Err(GraphusError::Storage(
                "a relationship full-text index must cover at least one type".to_owned(),
            ));
        }
        if if_not_exists
            && self.fulltext_equivalent_exists(
                name,
                FulltextEntity::Relationship,
                types,
                properties,
            )
        {
            return Ok(false);
        }
        if Self::name_used_by_other_catalog(self.store.borrow(), name, NameCatalog::Fulltext) {
            return Err(index_name_in_use(name));
        }

        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let entry = {
            let store = self.store.borrow_mut();
            let mut type_tokens = Vec::with_capacity(types.len());
            for ty in types {
                match store.intern_token(Namespace::RelType, ty) {
                    Ok(t) => {
                        if !type_tokens.contains(&t) {
                            type_tokens.push(t);
                        }
                    }
                    Err(e) => {
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            // Synchronous build → recorded `Online` (the relationship-property/composite precedent).
            let entry = FulltextIndexEntry {
                entity: FulltextEntity::Relationship,
                tokens: type_tokens,
                property_tokens,
                analyzer: analyzer.as_byte(),
                state: IndexState::Online,
            };
            store.set_fulltext_index(txn, name.to_owned(), entry.clone());
            entry
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing relationships
        // are indexed — `rebuild_index` scans the relationships, populates the rel-keyed inverted index,
        // and resets the shared full-text/spatial marker to the store's high-water.
        self.index.borrow_mut().register_fulltext_rel(
            name,
            entry.tokens,
            entry.property_tokens,
            analyzer,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(true)
    }

    /// Whether a full-text index equivalent to the requested `(name, entity, tokens, properties)`
    /// already exists (`rmp` #661, #663) — the same `name` in the full-text catalog, or the same covered
    /// `(entity, ordered label/type tuple, ordered property tuple)` under any name. Backs
    /// `CREATE FULLTEXT INDEX … IF NOT EXISTS` idempotency. Read-only, by token *lookup* (an unindexable
    /// token tuple means no index can cover it, so no equivalent exists).
    fn fulltext_equivalent_exists(
        &self,
        name: &str,
        entity: FulltextEntity,
        tokens: &[String],
        properties: &[String],
    ) -> bool {
        let store = self.store.borrow();
        if store.fulltext_index(name).is_some() {
            return true;
        }
        // Resolve the covering tokens in the right namespace (labels for a node index, rel types for a
        // relationship index) and the property tokens. A never-interned token means no index can cover
        // it, so no equivalent exists.
        let namespace = if entity.is_relationship() {
            Namespace::RelType
        } else {
            Namespace::Label
        };
        let mut token_ids = Vec::with_capacity(tokens.len());
        for tok in tokens {
            let Some(t) = store.token_id(namespace, tok) else {
                return false;
            };
            if !token_ids.contains(&t) {
                token_ids.push(t);
            }
        }
        let mut property_tokens = Vec::with_capacity(properties.len());
        for property in properties {
            let Some(t) = store.token_id(Namespace::PropKey, property) else {
                return false;
            };
            property_tokens.push(t);
        }
        store.fulltext_indexes().iter().any(|(_n, e)| {
            e.entity == entity && e.tokens == token_ids && e.property_tokens == property_tokens
        })
    }

    /// Drops the full-text index named `name` (`rmp` task #72): removes its durable catalog entry in a
    /// committed transaction, unregisters it from the in-memory [`IndexSet`], and cancels any
    /// in-progress build. Idempotent on a never-declared name (a clean no-op success).
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`, no
    /// such index) — the executor turns `false` into a `0` `indexes-removed` counter (`rmp` task #626
    /// follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_fulltext_index(&self, name: &str, if_exists: bool) -> Result<bool> {
        // Not declared: without `IF EXISTS` this is a `Neo.ClientError.Schema.IndexDropFailed` error
        // (Neo4j) and side-effect-free (nothing durable to remove). With `IF EXISTS` it is a clean no-op
        // success — defensively cancel any stray in-flight build + in-memory registration first
        // (`rmp` tasks #72, #661).
        if self.store.borrow().fulltext_index(name).is_none() {
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            self.cancel_fulltext_builds(name);
            // The name is unique across catalogs, so at most one of these unregisters anything
            // (`rmp` task #663): one is a no-op.
            self.index.borrow_mut().unregister_fulltext(name);
            self.index.borrow_mut().unregister_fulltext_rel(name);
            return Ok(false); // nothing removed.
        }
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_fulltext_index(txn, name);
        self.store.borrow_mut().commit(txn)?;

        self.cancel_fulltext_builds(name);
        // Unregister from whichever in-memory map holds it (node or relationship, `rmp` #663).
        self.index.borrow_mut().unregister_fulltext(name);
        self.index.borrow_mut().unregister_fulltext_rel(name);
        Ok(true) // an index was removed.
    }

    /// Lists every declared full-text index as `(name, entity, labels-or-types, properties, analyzer,
    /// state)` (`rmp` tasks #72, #663) for a `SHOW FULLTEXT INDEXES` surface. Reads the durable catalog
    /// and resolves the tokens back to names in the entity's namespace (labels for a node index, rel
    /// types for a relationship index); an entry whose tokens have no resolvable name (a
    /// defensively-skipped impossibility for a live token) or an unknown analyzer byte is omitted.
    /// Ordered by name.
    #[must_use]
    pub fn list_fulltext_indexes(&self) -> Vec<FulltextIndexListing> {
        let store = self.store.borrow();
        store
            .fulltext_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let token_namespace = if entry.entity.is_relationship() {
                    Namespace::RelType
                } else {
                    Namespace::Label
                };
                let mut labels_or_types = Vec::with_capacity(entry.tokens.len());
                for tok in &entry.tokens {
                    labels_or_types.push(store.token_name(token_namespace, *tok)?.to_owned());
                }
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                let analyzer = Analyzer::from_byte(entry.analyzer)?;
                // The EFFECTIVE state (`rmp` task #733): route by entity to the in-memory catalogue the
                // query seam actually consults, so a still-building (or fail-closed) index never reports
                // itself ONLINE — which is exactly what a `wait_for_indexes` poll keys on.
                let in_memory = if entry.entity.is_relationship() {
                    self.index.borrow().fulltext_rel_state(&name)
                } else {
                    self.index.borrow().fulltext_state(&name)
                };
                let state = Self::effective_state(entry.state, in_memory);
                Some((
                    name,
                    entry.entity,
                    labels_or_types,
                    properties,
                    analyzer,
                    state,
                ))
            })
            .collect()
    }

    /// Declares a **spatial (point) index** named `name` over `(label, property)`, **durably records
    /// it**, and starts a **non-blocking** background build of it (`rmp` task #98) — the spatial
    /// analogue of [`create_fulltext_index`](Self::create_fulltext_index).
    ///
    /// The label and property-key tokens are interned **durably** and the named catalog entry is
    /// recorded as [`IndexState::Populating`] — both in one committed transaction, so the
    /// *registration* survives a crash (an interrupted build recovers `Populating` and is completed by
    /// the open-time rebuild). The grid is registered in the in-memory [`IndexSet`] so concurrent
    /// writes maintain it from now on, and a pending build is enqueued; **no node is scanned here**, so
    /// the engine stays responsive. The build is advanced in bounded chunks by
    /// [`advance_index_builds`](Self::advance_index_builds) and promoted to [`IndexState::Online`] only
    /// when every snapshot node has been indexed — and only an `Online` spatial index drives a
    /// `SpatialIndexSeek` (see [`catalog`](Self::catalog) / [`IndexSet::online_spatial`]).
    ///
    /// Re-declaring an existing name **replaces** it (a fresh build over the new label/property).
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, the committing
    /// transaction, or the initial snapshot scan fails. On any error the index is left undeclared.
    pub fn create_point_index(
        &self,
        name: &str,
        label: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // `IF NOT EXISTS` (`rmp` #661): an equivalent index — the same `name` in the spatial catalog, or
        // the same covered `(label, property)` under any name — makes this an idempotent no-op (nothing
        // added), mirroring the node-property path.
        if if_not_exists && self.point_equivalent_exists(name, label, property) {
            return Ok(false);
        }
        // Names are globally unique across every schema catalog (`rmp` task #624): reject a name already
        // used by a *different* catalog (a re-declare within the spatial catalog keeps replace semantics).
        if Self::name_used_by_other_catalog(self.store.borrow(), name, NameCatalog::Spatial) {
            return Err(index_name_in_use(name));
        }
        // Intern the label + property-key tokens and record the durable catalog entry `Populating`, in
        // one committed transaction (so the schema change survives a crash atomically).
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            store.set_spatial_index(
                txn,
                name.to_owned(),
                SpatialIndexEntry {
                    entity: SpatialEntity::Node,
                    label_token,
                    property_token: prop_key,
                    state: IndexState::Populating,
                },
            );
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the grid `Populating` in the in-memory set so concurrent writes maintain it.
        self.index.borrow_mut().register_spatial(
            label_token,
            prop_key,
            graphus_index::DEFAULT_CELL_SIZE,
            IndexState::Populating,
        );

        // Cancel any prior build of the same name — pending OR parked poisoned (`rmp` task #573) — then
        // enqueue this one. A parked build left behind would be resurrected later and race this one.
        Self::cancel_named_builds(
            &mut builds.pending_spatial_builds,
            &mut builds.poisoned_spatial_builds,
            name,
            |b| &b.name,
        );
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        builds
            .pending_spatial_builds
            .push_back(PendingSpatialBuild {
                name: name.to_owned(),
                label_token,
                prop_key,
                snapshot,
                cursor: 0,
                generation: self.index.borrow().wipe_generation(),
                stall: BUILD_STALL_BUDGET,
            });
        Ok(true)
    }

    /// Declares a **relationship** spatial (point) index named `name` over `(rel_type, property)`
    /// (`rmp` task #664) — the relationship analogue of [`create_point_index`](Self::create_point_index).
    ///
    /// Unlike the node point index (which builds non-blockingly), the relationship index is built
    /// **synchronously and recorded `Online`** in one committed transaction, then a full
    /// [`rebuild_index`](Self::rebuild_index) repopulates its rel-keyed grid from the store — exactly the
    /// pattern the relationship full-text (`rmp` #663) and relationship-property (`rmp` #646) indexes
    /// use. `rebuild_index` also resets the shared full-text/spatial freshness marker to the store's
    /// high-water, so a reader whose snapshot predates the build declines to the correct scan path.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// Returns a storage error if interning any token, recording the catalog entry, or the committing
    /// transaction fails; `Neo.ClientError.Schema.IndexWithNameAlreadyExists` when `name` is already
    /// taken by another schema catalog. On any error the index is left undeclared.
    pub fn create_point_rel_index(
        &self,
        name: &str,
        rel_type: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // `IF NOT EXISTS` (`rmp` #661): an equivalent relationship point index — the same name, or the
        // same covered `(type, property)` under any name — makes this an idempotent no-op.
        if if_not_exists && self.point_rel_equivalent_exists(name, rel_type, property) {
            return Ok(false);
        }
        // Names are globally unique across every schema catalog (`rmp` task #624).
        if Self::name_used_by_other_catalog(self.store.borrow(), name, NameCatalog::Spatial) {
            return Err(index_name_in_use(name));
        }
        // Intern the rel-type + property-key tokens and record the durable catalog entry `Online`
        // (synchronous build), in one committed transaction (so the schema change survives a crash).
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        {
            let store = self.store.borrow_mut();
            let type_token = match store.intern_token(Namespace::RelType, rel_type) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            store.set_spatial_index(
                txn,
                name.to_owned(),
                SpatialIndexEntry {
                    entity: SpatialEntity::Relationship,
                    label_token: type_token,
                    property_token: prop_key,
                    state: IndexState::Online,
                },
            );
        }
        self.store.borrow_mut().commit(txn)?;

        // Register the grid `Online` in the in-memory set and (re)build it so existing relationships are
        // indexed — `rebuild_index` scans the relationships, populates the rel-keyed grid, and resets the
        // shared full-text/spatial marker to the store's high-water.
        let type_token = self
            .store
            .borrow()
            .token_id(Namespace::RelType, rel_type)
            .expect("INVARIANT: the rel-type token was just interned in the committed transaction");
        let prop_key = self
            .store
            .borrow()
            .token_id(Namespace::PropKey, property)
            .expect(
                "INVARIANT: the property-key token was just interned in the committed transaction",
            );
        self.index.borrow_mut().register_spatial_rel(
            type_token,
            prop_key,
            graphus_index::DEFAULT_CELL_SIZE,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(true)
    }

    /// Whether a spatial (point) index equivalent to the requested `(name, label, property)` already
    /// exists (`rmp` #661) — the same `name` in the spatial catalog, or the same covered
    /// `(label, property)` under any name. Backs `CREATE POINT INDEX … IF NOT EXISTS` idempotency.
    /// Read-only, by token *lookup*.
    fn point_equivalent_exists(&self, name: &str, label: &str, property: &str) -> bool {
        let store = self.store.borrow();
        if store.spatial_index(name).is_some() {
            return true;
        }
        let props = [property.to_owned()];
        let Some((label_token, property_tokens)) =
            Self::resolve_property_tokens(store, label, &props)
        else {
            return false;
        };
        let prop_token = property_tokens[0];
        store.spatial_indexes().iter().any(|(_n, e)| {
            // A node index equivalence: a relationship point index (same numeric token in a different
            // namespace) is never equivalent (`rmp` task #664).
            !e.entity.is_relationship()
                && e.label_token == label_token
                && e.property_token == prop_token
        })
    }

    /// Whether a **relationship** spatial (point) index equivalent to the requested `(name, type,
    /// property)` already exists (`rmp` task #664) — the same `name` in the spatial catalog, or the same
    /// covered `(type, property)` under any name. Backs `CREATE POINT INDEX … FOR ()-[r:T]-() … IF NOT
    /// EXISTS` idempotency. Read-only, by token *lookup*.
    fn point_rel_equivalent_exists(&self, name: &str, rel_type: &str, property: &str) -> bool {
        let store = self.store.borrow();
        if store.spatial_index(name).is_some() {
            return true;
        }
        let Some(type_token) = store.token_id(Namespace::RelType, rel_type) else {
            return false;
        };
        let Some(prop_token) = store.token_id(Namespace::PropKey, property) else {
            return false;
        };
        store.spatial_indexes().iter().any(|(_n, e)| {
            e.entity.is_relationship()
                && e.label_token == type_token
                && e.property_token == prop_token
        })
    }

    /// Drops the spatial (point) index named `name` (`rmp` task #98): removes its durable catalog
    /// entry in a committed transaction, unregisters its grid from the in-memory [`IndexSet`], and
    /// cancels any in-progress build. Idempotent on a never-declared name (a clean no-op success).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_point_index(&self, name: &str, if_exists: bool) -> Result<bool> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // Resolve the covered `(label_token, prop_key)` from the durable entry so we can unregister the
        // right grid from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().spatial_index(name);
        let Some(entry) = entry else {
            // Not declared: without `IF EXISTS` this is a `Neo.ClientError.Schema.IndexDropFailed`
            // error (Neo4j) and side-effect-free. With `IF EXISTS` it is a clean no-op success —
            // defensively cancel any stray in-flight build first (`rmp` tasks #98, #661).
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            Self::cancel_named_builds(
                &mut builds.pending_spatial_builds,
                &mut builds.poisoned_spatial_builds,
                name,
                |b| &b.name,
            );
            return Ok(false); // nothing removed.
        };

        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_spatial_index(txn, name);
        self.store.borrow_mut().commit(txn)?;

        Self::cancel_named_builds(
            &mut builds.pending_spatial_builds,
            &mut builds.poisoned_spatial_builds,
            name,
            |b| &b.name,
        );
        // Route the unregister by entity (`rmp` task #664): a relationship point index lives in the
        // rel-keyed grid map, a node one in the node-keyed map (both keyed by `(token, prop_key)`).
        if entry.entity.is_relationship() {
            self.index
                .borrow_mut()
                .unregister_spatial_rel(entry.label_token, entry.property_token);
        } else {
            self.index
                .borrow_mut()
                .unregister_spatial(entry.label_token, entry.property_token);
        }
        Ok(true) // an index was removed.
    }

    /// Lists every declared **node** spatial (point) index as `(name, label, property, state)`
    /// (`rmp` tasks #98, #664) for a `SHOW POINT INDEXES` surface. Reads the durable catalog and resolves
    /// the tokens back to names; a **relationship** point index (`rmp` #664) and an entry whose tokens
    /// have no resolvable name (a defensively-skipped impossibility for a live token) are omitted.
    /// Ordered by name.
    #[must_use]
    pub fn list_point_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .spatial_indexes()
            .into_iter()
            .filter(|(_n, entry)| !entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .spatial_state(entry.label_token, entry.property_token),
                );
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Lists every declared **relationship** spatial (point) index as `(name, type, property, state)`
    /// (`rmp` task #664) for the `SHOW INDEXES` surface. Reads the durable catalog and resolves the rel
    /// type + property tokens back to names; a node point index and an entry whose tokens have no
    /// resolvable name are omitted. Ordered by name — the relationship analogue of
    /// [`list_point_indexes`](Self::list_point_indexes).
    #[must_use]
    pub fn list_point_rel_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .spatial_indexes()
            .into_iter()
            .filter(|(_n, entry)| entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .spatial_rel_state(entry.label_token, entry.property_token),
                );
                let rel_type = store.token_name(Namespace::RelType, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, rel_type.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Declares a text (trigram) node index named `name` over `(label, property)` (`rmp` task #662),
    /// enforcing Neo4j-conformant schema semantics. A `TEXT` index accelerates `CONTAINS` / `ENDS WITH`
    /// / `STARTS WITH` — the substring/suffix predicates a forward-ordered range index cannot serve.
    ///
    /// The label + property-key tokens are interned **durably** and the named catalog entry is recorded
    /// as [`IndexState::Online`] in one committed transaction (so the *registration* survives a crash),
    /// then the index is registered in the in-memory [`IndexSet`] and **synchronously built** from the
    /// current nodes. The synchronous build is crash-safe: the backing trigram index is ephemeral and
    /// rebuilt from the durable catalog + store on open, so a crash mid-build recovers the `Online`
    /// registration and repopulates it — recovery never observes a half-built index. This mirrors the
    /// composite index (`rmp` task #657) rather than the non-blocking spatial/full-text builds.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent text index on `(label, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema catalog;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build
    ///   scan fails. On any error the index is left undeclared.
    pub fn create_text_index(
        &self,
        name: &str,
        label: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // 1. Equivalent-index check (a text index on the same `(label, property)` under any name, or the
        //    same `name`): `IF NOT EXISTS` makes it an idempotent no-op, else it is an error. A text
        //    index is DISTINCT from a range index over the same `(label, property)` — both may coexist in
        //    Neo4j — so this consults only the text catalog.
        if self.text_equivalent_exists(name, label, property) {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(equivalent_index_exists(label, property))
            };
        }
        // 2. Names are globally unique across every schema catalog (`rmp` task #624): reject a name
        //    already used by a *different* catalog (a re-declare within the text catalog is caught by the
        //    equivalence check above, so it never reaches here).
        if Self::name_used_by_other_catalog(self.store.borrow(), name, NameCatalog::Text) {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(name))
            };
        }
        // 3. Intern the label + property-key tokens and record the durable catalog entry `Online` in one
        //    committed transaction — so the schema change survives a crash atomically.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            store.set_text_index(
                txn,
                name.to_owned(),
                TextIndexEntry {
                    label_token,
                    property_token: prop_key,
                    state: IndexState::Online,
                },
            );
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // 4. Register the trigram index **`Populating`** so the write path maintains it from now on
        //    while the build runs, then synchronously index the existing nodes, and only THEN promote it
        //    to `Online`. The order is what makes it safe (`rmp` task #733): the index becomes visible
        //    to readers (the planner's catalog and the `index_seek_text` seam both gate on `Online`)
        //    only once it is COMPLETE. Registering `Online` up front — as this did before — meant that a
        //    fault in the scan below returned an error to the client but left behind an `Online`, EMPTY
        //    trigram index, after which every `CONTAINS` / `STARTS WITH` / `ENDS WITH` on the covered
        //    property silently returned no rows until the process restarted.
        //
        //    The index is ephemeral (rebuilt on open from the durable catalog + store), so this
        //    synchronous fill is a pure in-memory build with no durability surface — a crash before it
        //    finishes recovers the durable `Online` registration and the open-time rebuild repopulates
        //    it store-consistently.
        self.index
            .borrow_mut()
            .register_text(label_token, prop_key, IndexState::Populating);
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                // The build could not start. Leave the in-memory index `Populating` (declined by every
                // reader, which falls back to the exact label scan + residual) and surface the error.
                // The durable entry stays `Online`, so re-opening the store — or any later successful
                // `rebuild_index` — repopulates and promotes it. Never `Online` and empty.
                return Err(e);
            }
        };
        let registered = vec![(label_token, prop_key)];
        self.index.borrow_mut().clear_rebuild_gap();
        for id in node_ids {
            Self::index_one_node_text(&self.store, &self.index, id, &registered);
        }
        // A node the fill could not read is missing from the trigram index for good (`rmp` task #733):
        // the residual `CONTAINS` filter can drop a candidate but never add one back. Leave the index
        // `Populating` (declined by every reader, which falls back to the exact label scan) and surface
        // the fault, rather than publish an index with a hole in it.
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            // `rmp` #803: see the vector twin — discard the fill loop's transient dirty flag.
            self.index.borrow_mut().clear_ft_spatial_dirty();
            return Err(GraphusError::Storage(format!(
                "the text index {name:?} could not be built: the store scan skipped at least one node"
            )));
        }
        // The trigram index now holds every existing node's terms: promote it so readers may use it.
        self.index
            .borrow_mut()
            .set_text_state(label_token, prop_key, IndexState::Online);

        // 5. Stamp the cross-snapshot freshness marker (`rmp` task #467): the trigram index now reflects
        //    committed state at the store's current high-water, and the build raised the transient dirty
        //    flag on every insert. Bump the marker to the high-water so a reader whose snapshot predates
        //    the build declines to the always-correct scan path, and clear the build's dirty flag so it
        //    does not leak into the next user statement (as `bump_ft_spatial_marker_after_build` does).
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);
        Ok(true) // the index was created.
    }

    /// Whether a text (trigram) index equivalent to the requested `(name, label, property)` already
    /// exists (`rmp` task #662) — the same `name` in the text catalog, or the same covered
    /// `(label, property)` under any name. Backs `CREATE TEXT INDEX … IF NOT EXISTS` idempotency.
    /// Read-only, by token *lookup*. Consults ONLY the text catalog: a range/point index over the same
    /// `(label, property)` is a different kind and does not make a text index "equivalent".
    fn text_equivalent_exists(&self, name: &str, label: &str, property: &str) -> bool {
        let store = self.store.borrow();
        if store.text_index(name).is_some() {
            return true;
        }
        let props = [property.to_owned()];
        let Some((label_token, property_tokens)) =
            Self::resolve_property_tokens(store, label, &props)
        else {
            return false;
        };
        let prop_token = property_tokens[0];
        store
            .text_indexes()
            .iter()
            .any(|(_n, e)| e.label_token == label_token && e.property_token == prop_token)
    }

    /// Drops the text (trigram) index named `name` (`rmp` task #662): removes its durable catalog entry
    /// in a committed transaction and unregisters its trigram index from the in-memory [`IndexSet`].
    /// Idempotent on a never-declared name (a clean no-op success under `if_exists`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` when the index is not declared and `if_exists` is
    ///   `false`;
    /// - a storage error if the committing transaction fails.
    pub fn drop_text_index(&self, name: &str, if_exists: bool) -> Result<bool> {
        // Resolve the covered `(label_token, prop_key)` from the durable entry so we can unregister the
        // right trigram index from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().text_index(name);
        let Some(entry) = entry else {
            // Not declared: without `IF EXISTS` this is a `Neo.ClientError.Schema.IndexDropFailed` error
            // (Neo4j) and side-effect-free. With `IF EXISTS` it is a clean no-op success.
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            return Ok(false); // nothing removed.
        };

        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_text_index(txn, name);
        self.store.borrow_mut().commit(txn)?;

        self.index
            .borrow_mut()
            .unregister_text(entry.label_token, entry.property_token);
        Ok(true) // an index was removed.
    }

    /// Lists every declared text (trigram) index as `(name, label, property, state)` (`rmp` task #662),
    /// for a `SHOW INDEXES` surface. Reads the durable catalog and resolves the tokens back to names; an
    /// entry whose tokens have no resolvable name (a defensively-skipped impossibility for a live token)
    /// is omitted. Ordered by name.
    #[must_use]
    pub fn list_text_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .text_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .text_state(entry.label_token, entry.property_token),
                );
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    // ---- Vector (HNSW) index surface (`rmp` task #669) --------------------------------------------

    /// Declares a **vector (HNSW) index** — over a node label (`entity == VectorEntity::Node`) or a
    /// relationship type (`entity == VectorEntity::Relationship`) — named `name` (or an auto-name when
    /// `None`) over `(covering, property)`, **durably records it**, and **synchronously builds** it from
    /// the current data (`rmp` task #669). The single coordinator entry point behind
    /// `CREATE VECTOR INDEX … FOR (n:L) ON (n.p)` / `FOR ()-[r:T]-() ON (r.p)` (the DDL surface is
    /// `rmp` #671, part C/D).
    ///
    /// The covering + property-key tokens are interned **durably** and the named catalog entry — carrying
    /// the entity, the embedding `dimensions`, the `similarity` metric and the HNSW `m` /
    /// `ef_construction` parameters — is recorded [`IndexState::Online`] in one committed transaction (so
    /// the *registration* survives a crash), then the HNSW graph is registered in the in-memory
    /// [`IndexSet`] and synchronously filled from the current nodes / relationships. The synchronous fill
    /// is crash-safe: the graph is ephemeral and rebuilt from the durable catalog + store on open, so a
    /// crash mid-build recovers the `Online` registration and repopulates it store-consistently — exactly
    /// like the text (`rmp` #662) and composite (`rmp` #657) indexes.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// - a storage error when `dimensions == 0` (a zero-dimension embedding is meaningless);
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent vector index on `(entity, covering, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build scan
    ///   fails. On any error the index is left undeclared.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_online_vector_index_named(
        &self,
        name: Option<&str>,
        entity: VectorEntity,
        covering: &str,
        property: &str,
        dimensions: usize,
        similarity: VectorSimilarity,
        m: usize,
        ef_construction: usize,
        if_not_exists: bool,
    ) -> Result<bool> {
        if dimensions == 0 {
            return Err(GraphusError::Runtime(
                "a vector index dimension must be greater than zero".to_owned(),
            ));
        }
        let namespace = if entity.is_relationship() {
            Namespace::RelType
        } else {
            Namespace::Label
        };

        // 1. Equivalent-index check (read-only, by token *lookup*): the same covered
        //    `(entity, covering, property)` under any name makes this an idempotent no-op (or an error
        //    without `IF NOT EXISTS`). An absent token means no index can cover this target.
        let equivalent_exists = {
            let store = self.store.borrow();
            match (
                store.token_id(namespace, covering),
                store.token_id(Namespace::PropKey, property),
            ) {
                (Some(token), Some(prop_token)) => store
                    .vector_index_name_for(entity, token, prop_token)
                    .is_some(),
                _ => false,
            }
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false)
            } else if entity.is_relationship() {
                Err(equivalent_rel_index_exists(covering, property))
            } else {
                Err(equivalent_index_exists(covering, property))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3.
        if let Some(n) = name
            && Self::name_in_use(self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) in one committed
        //    transaction — so the schema change survives a crash atomically.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let (token, prop_key) = {
            let store = self.store.borrow_mut();
            let token = match store.intern_token(namespace, covering) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_vector_index_name(store, entity, covering, property),
            };
            store.set_vector_index(
                txn,
                effective_name,
                VectorIndexEntry {
                    entity,
                    token,
                    property_token: prop_key,
                    dimensions: dimensions as u32,
                    similarity,
                    m: m as u32,
                    ef_construction: ef_construction as u32,
                    state: IndexState::Online,
                },
            );
            (token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // 4. Register the HNSW graph **`Populating`** in the in-memory set so concurrent writes maintain
        //    it while the build runs, synchronously index the existing nodes / relationships into it, and
        //    only THEN promote it to `Online` (`rmp` task #733). The order is the safety property: a
        //    vector index is the one kind with **no scan fallback** (an approximate structure cannot be
        //    re-derived exactly by brute force), so an `Online`-but-empty HNSW would answer every k-NN
        //    with an empty neighbour set — indistinguishable, to the caller, from "there are no near
        //    neighbours". Registering `Online` up front (as this did before) left exactly that state
        //    behind whenever the scan below faulted. While `Populating`, the query seam returns a clear
        //    "still populating" error instead. The graph is ephemeral (rebuilt on open), so this
        //    synchronous fill has no durability surface.
        let sim = similarity_from_storage(similarity);
        if entity.is_relationship() {
            self.index.borrow_mut().register_vector_rel(
                token,
                prop_key,
                dimensions,
                sim,
                m,
                ef_construction,
                IndexState::Populating,
            );
            // The build could not start: `?` leaves the index `Populating` (its query seam then raises a
            // clear "still populating" error) and surfaces the fault. A reopen — or any later successful
            // `rebuild_index` — repopulates it from the durable catalog and promotes it.
            let rel_ids = self.store.borrow().scan_rel_ids()?;
            let registered = vec![(token, prop_key)];
            self.index.borrow_mut().clear_rebuild_gap();
            for id in rel_ids {
                Self::index_one_rel_vector(&self.store, &self.index, id, &registered);
            }
            // A relationship the fill could not read is missing from the HNSW for good, and a vector index
            // has no scan fallback that could compensate (`rmp` task #733). Leave it `Populating` — its
            // query seam then raises a clear "still populating" error — and surface the fault.
            if self.index.borrow().rebuild_gap() {
                self.index.borrow_mut().clear_rebuild_gap();
                // `rmp` #803: this bail is AFTER the fill loop, which raised the transient dirty flag.
                // Discard it — the build's insertions reflect committed state and must never be
                // attributed to (or poison on the abort of) the next unrelated write statement.
                self.index.borrow_mut().clear_ft_spatial_dirty();
                return Err(GraphusError::Storage(
                    "the vector index could not be built: the store scan skipped at least one \
                     relationship"
                        .to_owned(),
                ));
            }
            self.index
                .borrow_mut()
                .set_vector_rel_state(token, prop_key, IndexState::Online);
        } else {
            self.index.borrow_mut().register_vector(
                token,
                prop_key,
                dimensions,
                sim,
                m,
                ef_construction,
                IndexState::Populating,
            );
            // As above: a fault leaves the index `Populating`, never `Online` and empty.
            let node_ids = self.store.borrow_mut().scan_node_ids()?;
            let registered = vec![(token, prop_key)];
            self.index.borrow_mut().clear_rebuild_gap();
            for id in node_ids {
                Self::index_one_node_vector(&self.store, &self.index, id, &registered);
            }
            // The node twin of the guard above (`rmp` task #733).
            if self.index.borrow().rebuild_gap() {
                self.index.borrow_mut().clear_rebuild_gap();
                // `rmp` #803: this bail is AFTER the fill loop, which raised the transient dirty flag.
                // Discard it — the build's insertions reflect committed state and must never be
                // attributed to (or poison on the abort of) the next unrelated write statement.
                self.index.borrow_mut().clear_ft_spatial_dirty();
                return Err(GraphusError::Storage(
                    "the vector index could not be built: the store scan skipped at least one node"
                        .to_owned(),
                ));
            }
            self.index
                .borrow_mut()
                .set_vector_state(token, prop_key, IndexState::Online);
        }

        // 5. Stamp the cross-snapshot freshness marker (`rmp` task #467): the HNSW graph now reflects
        //    committed state at the store's high-water, and the build raised the transient dirty flag on
        //    every insert. Bump the marker so a reader whose snapshot predates the build declines to the
        //    always-correct scan path, and clear the build's dirty flag so it does not leak into the next
        //    statement — exactly like the text index create.
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);
        Ok(true)
    }

    /// A globally-unique, deterministic auto-name for the vector index on `(entity, covering, property)`
    /// (`rmp` task #669) — the vector analogue of
    /// [`unique_auto_index_name`](Self::unique_auto_index_name). The equivalence check in the caller has
    /// already guaranteed no vector index covers this exact target, so the base name can only collide
    /// with an *unrelated* schema rule; a numeric counter resolves any residual collision so the returned
    /// name is free across **every** catalog.
    fn unique_auto_vector_index_name(
        store: &RecordStore<D, S>,
        entity: VectorEntity,
        covering: &str,
        property: &str,
    ) -> String {
        let base = if entity.is_relationship() {
            auto_vector_rel_index_name(covering, property)
        } else {
            auto_vector_index_name(covering, property)
        };
        if !Self::name_in_use(store, &base) {
            return base;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{base}_{n}");
            if !Self::name_in_use(store, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Drops the vector (HNSW) index named `name` (`rmp` task #669): removes its durable catalog entry in
    /// a committed transaction and unregisters its HNSW graph from the in-memory [`IndexSet`] (routing by
    /// entity to the node- or relationship-keyed map). Idempotent on a never-declared name under
    /// `if_exists`.
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` when the index is not declared and `if_exists` is
    ///   `false`;
    /// - a storage error if the committing transaction fails.
    pub fn drop_vector_index(&self, name: &str, if_exists: bool) -> Result<bool> {
        // Resolve the covered `(entity, token, prop_key)` from the durable entry so we can unregister the
        // right graph from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().vector_index(name);
        let Some(entry) = entry else {
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            return Ok(false); // nothing removed.
        };

        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_vector_index(txn, name);
        self.store.borrow_mut().commit(txn)?;

        if entry.entity.is_relationship() {
            self.index
                .borrow_mut()
                .unregister_vector_rel(entry.token, entry.property_token);
        } else {
            self.index
                .borrow_mut()
                .unregister_vector(entry.token, entry.property_token);
        }
        Ok(true) // an index was removed.
    }

    /// Lists every declared **node** vector index as `(name, label, property, state)` (`rmp` task #669)
    /// for a `SHOW VECTOR INDEXES` surface. Reads the durable catalog and resolves the tokens back to
    /// names; a **relationship** vector index and an entry whose tokens have no resolvable name are
    /// omitted. Ordered by name.
    #[must_use]
    pub fn list_vector_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .vector_indexes()
            .into_iter()
            .filter(|(_n, entry)| !entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .vector_state(entry.token, entry.property_token),
                );
                let label = store.token_name(Namespace::Label, entry.token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Lists every declared **relationship** vector index as `(name, type, property, state)`
    /// (`rmp` task #669) — the relationship analogue of
    /// [`list_vector_indexes`](Self::list_vector_indexes). Ordered by name.
    #[must_use]
    pub fn list_vector_rel_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .vector_indexes()
            .into_iter()
            .filter(|(_n, entry)| entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .vector_rel_state(entry.token, entry.property_token),
                );
                let rel_type = store.token_name(Namespace::RelType, entry.token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, rel_type.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Lists every declared vector index — node **and** relationship — as a [`VectorIndexListing`]
    /// carrying its full `indexConfig` (`rmp` task #671), for the unified `SHOW INDEXES` VECTOR rows.
    /// Reads the durable catalog and resolves each covered token (by [`entity`](VectorIndexListing::entity)
    /// namespace) plus the property token back to names; an entry whose tokens have no resolvable name is
    /// omitted. Ordered by name (the catalog's [`BTreeMap`](std::collections::BTreeMap) order).
    #[must_use]
    pub fn list_vector_index_listings(&self) -> Vec<VectorIndexListing> {
        let store = self.store.borrow();
        store
            .vector_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let namespace = if entry.entity.is_relationship() {
                    Namespace::RelType
                } else {
                    Namespace::Label
                };
                let label_or_type = store.token_name(namespace, entry.token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                // The EFFECTIVE state (`rmp` task #733), routed by entity — a vector index that is not
                // usable ERRORS on query, so reporting it ONLINE would be doubly misleading.
                let in_memory = if entry.entity.is_relationship() {
                    self.index
                        .borrow()
                        .vector_rel_state(entry.token, entry.property_token)
                } else {
                    self.index
                        .borrow()
                        .vector_state(entry.token, entry.property_token)
                };
                let state = Self::effective_state(entry.state, in_memory);
                Some(VectorIndexListing {
                    name,
                    entity: entry.entity,
                    label_or_type: label_or_type.to_owned(),
                    property: property.to_owned(),
                    dimensions: entry.dimensions,
                    similarity: entry.similarity,
                    m: entry.m,
                    ef_construction: entry.ef_construction,
                    state,
                })
            })
            .collect()
    }

    /// The `k` nearest **node** ids to `query` in the vector index over `(label, property)`, as
    /// `(id, score)` by descending score (`rmp` task #669) — the seek primitive the query planner
    /// (`rmp` #671) will build on. [`None`] when the label / property tokens are unknown or no vector
    /// index covers them; `Some(Err)` on a query-dimension mismatch; otherwise `Some(Ok(hits))`.
    ///
    /// The returned ids are **candidates**: the query planner layers MVCC visibility + current-label +
    /// current-value re-checks (and the cross-snapshot freshness gate) on top. `ef_search` defaults are
    /// the caller's; [`graphus_index::DEFAULT_EF_SEARCH`] is a sensible starting point.
    ///
    /// # This is the RAW seam and is NOT safe for production reads (`rmp` #797)
    ///
    /// It reads the ANN graph directly and applies **none** of the guarantees the query surface applies.
    /// Specifically it does not check [`IndexState`] (`rmp` #733), so a still-`Populating` or
    /// fail-closed index answers with a silently truncated or empty neighbour set; it does not consult
    /// the `rmp` #780 build-conflict gate, so an index whose build was blocked by an uncommitted writer
    /// answers from an incomplete graph instead of declining to the exact scan; and the scores it
    /// returns are **provisional**, computed from whatever vector the graph holds rather than from the
    /// caller's snapshot-visible embedding.
    ///
    /// Production reads MUST go through `db.index.vector.queryNodes`, i.e.
    /// [`GraphAccess::vector_query_nodes`](crate::graph_access::GraphAccess::vector_query_nodes), which
    /// applies all three. This entry point exists for tests and for low-level index inspection; it has
    /// no production caller today and must not acquire one without first gaining those gates.
    #[must_use]
    pub fn vector_query_nodes(
        &self,
        label: &str,
        property: &str,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Option<std::result::Result<Vec<(u64, f32)>, VectorIndexError>> {
        let (label_token, prop_key) = {
            let store = self.store.borrow();
            (
                store.token_id(Namespace::Label, label)?,
                store.token_id(Namespace::PropKey, property)?,
            )
        };
        self.index
            .borrow()
            .seek_vector_knn(label_token, prop_key, query, k, ef_search)
    }

    /// The `k` nearest **relationship** ids to `query` in the vector index over `(rel_type, property)`
    /// (`rmp` task #669) — the relationship analogue of
    /// [`vector_query_nodes`](Self::vector_query_nodes).
    #[must_use]
    pub fn vector_query_rels(
        &self,
        rel_type: &str,
        property: &str,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Option<std::result::Result<Vec<(u64, f32)>, VectorIndexError>> {
        let (type_token, prop_key) = {
            let store = self.store.borrow();
            (
                store.token_id(Namespace::RelType, rel_type)?,
                store.token_id(Namespace::PropKey, property)?,
            )
        };
        self.index
            .borrow()
            .seek_vector_rel_knn(type_token, prop_key, query, k, ef_search)
    }

    /// Idempotency-aware `CREATE CONSTRAINT` entry point (`rmp` #638): wraps
    /// [`create_constraint_general`](Self::create_constraint_general) with `IF NOT EXISTS` and
    /// `OR REPLACE` handling, returning whether the schema was **actually mutated** (which drives the
    /// DDL summary's `constraints-added` counter — a no-op reports `0`).
    ///
    /// * `or_replace` — drop any same-named constraint first, then create; a replace always mutates
    ///   (`Ok(true)`). A **Graphus superset** of the Neo4j constraint surface (which offers only
    ///   `IF NOT EXISTS`).
    /// * `if_not_exists` — if a constraint with the same `name`, or an **equivalent** one (same
    ///   covering token + property tuple + kind + declared type, possibly under another name), already
    ///   exists, this is an idempotent no-op success (`Ok(false)`); otherwise it creates (`Ok(true)`).
    /// * neither — create, surfacing a name-in-use error on a colliding name.
    ///
    /// `covering` is the label name (node kinds) or the relationship-type name (relationship kinds);
    /// the namespace is derived from `kind`.
    ///
    /// # Errors
    /// Propagates any [`create_constraint_general`](Self::create_constraint_general) or
    /// [`drop_constraint`](Self::drop_constraint) error (a constraint violation or storage fault); on
    /// any error the schema is left unchanged (the drop-then-create is not atomic across the two, but
    /// each step is individually transactional, and a failed create after a successful `OR REPLACE`
    /// drop leaves the name free — matching the operator's intent to replace).
    #[allow(clippy::too_many_arguments)]
    pub fn create_constraint_ddl(
        &self,
        name: &str,
        covering: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
        if_not_exists: bool,
        or_replace: bool,
    ) -> Result<bool> {
        self.create_constraint_ddl_cancellable(
            name,
            covering,
            properties,
            kind,
            type_descriptor,
            if_not_exists,
            or_replace,
            &CancellationToken::new(),
        )
    }

    /// [`create_constraint_ddl`](Self::create_constraint_ddl) with a **cancellation token** the
    /// validation walk polls, so an operator can abort a long-running `CREATE CONSTRAINT` with
    /// `TERMINATE TRANSACTIONS` (`rmp` task #903).
    ///
    /// The naming mirrors the executor's own
    /// [`execute_with_extensions_cancellable`](crate::executor::execute_with_extensions_cancellable):
    /// the plain entry point is the same call with a token that is never cancelled, so no existing
    /// caller changes behaviour.
    ///
    /// # Why a parameter and not a field on the coordinator
    ///
    /// A token stored on `self` and cleared after the call is a latch, and a latch that survives one
    /// early return poisons every later DDL in the process — the exact shape of the `rmp` #467/#803
    /// full-text marker defect. Passing it explicitly makes its lifetime the call's lifetime.
    ///
    /// # Errors
    /// As [`create_constraint_ddl`](Self::create_constraint_ddl), plus a
    /// [`GraphusError::Transaction`] when the token is cancelled during validation. A cancelled DDL
    /// has **zero** side effects — see
    /// [`create_constraint_general_cancellable`](Self::create_constraint_general_cancellable).
    #[allow(clippy::too_many_arguments)]
    pub fn create_constraint_ddl_cancellable(
        &self,
        name: &str,
        covering: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
        if_not_exists: bool,
        or_replace: bool,
        cancel: &CancellationToken,
    ) -> Result<bool> {
        if or_replace {
            // The `rmp` #902 concurrency guard is applied HERE, before the drop, and not once at the
            // top of this function: an `OR REPLACE` drops before it creates, so refusing only inside
            // the create would leave the operator with the old constraint dropped and the new one not
            // declared — for a condition a retry would have cleared. Every other arm reaches the same
            // guard inside `create_constraint_general`, *after* the resolutions below.
            self.refuse_constraint_ddl_while_writers_open(name)?;
            // The cancellation pre-flight runs HERE, before the drop, for exactly the reason the #902
            // guard above does (`rmp` task #903). An `OR REPLACE` drops before it creates, so a
            // cancellation observed only inside the create would leave the operator with the old
            // constraint gone and the new one not declared — the one half-applied state this command
            // must never produce. Checked once here; the create below re-checks per entity, and
            // cancelling *it* leaves precisely the state a failed re-create already leaves.
            Self::check_constraint_ddl_cancelled(name, cancel)?;
            // Drop any existing constraint of this name, then (re)create. A replace always mutates.
            let _ = self.drop_constraint(name)?;
            self.create_constraint_general_cancellable(
                name,
                covering,
                properties,
                kind,
                type_descriptor,
                cancel,
            )?;
            return Ok(true);
        }
        // Detect any conflict once (read-only): a same-name constraint, or an equivalent-schema one.
        // Resolved BEFORE the `rmp` #902 concurrency guard (which `create_constraint_general` applies),
        // so that neither of the two answers below is displaced by it:
        //
        // * an `IF NOT EXISTS` that resolves to an existing equivalent constraint validates nothing and
        //   decides nothing, so there is no stale data to be misled by and no reason to refuse it. This
        //   is the canonical application-startup idiom — refusing it on a busy server would make every
        //   boot load-dependent for a call that changes nothing.
        // * a name/schema conflict is a PERMANENT error. Reporting it as the retryable transaction error
        //   would make drivers retry (`Neo.TransientError` is retryable by contract) a call that cannot
        //   ever succeed, and then surface a different error once the writer happened to close.
        let name_taken = self.store.borrow().constraint(name).is_some();
        let schema_taken =
            self.constraint_schema_exists(covering, properties, kind, type_descriptor.as_ref());
        if if_not_exists {
            // `IF NOT EXISTS`: an equivalent existing constraint (by name or schema) is a no-op.
            if name_taken || schema_taken {
                return Ok(false); // idempotent no-op: nothing added.
            }
        } else {
            // Plain `CREATE CONSTRAINT`: a same-name or same-schema constraint is a conflict (matching
            // Neo4j, which requires `IF NOT EXISTS`/`OR REPLACE` to reconcile). This is what makes
            // `IF NOT EXISTS` semantically meaningful.
            if name_taken {
                return Err(constraint_name_in_use(name));
            }
            if schema_taken {
                return Err(equivalent_constraint_exists(covering, properties));
            }
        }
        self.create_constraint_general_cancellable(
            name,
            covering,
            properties,
            kind,
            type_descriptor,
            cancel,
        )?;
        Ok(true)
    }

    /// Whether a constraint with the **same schema** — covering token + property tuple + kind + type
    /// descriptor (possibly under a different name) — already exists (`rmp` #638). Read-only; an absent
    /// covering/property token means the covered label/type or property has never been seen, so no such
    /// schema exists yet.
    fn constraint_schema_exists(
        &self,
        covering: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<&ConstraintTypeDescriptor>,
    ) -> bool {
        let store = self.store.borrow();
        let namespace = constraint_covering_namespace(kind);
        let Some(covering_token) = store.token_id(namespace, covering) else {
            return false;
        };
        let mut prop_tokens = Vec::with_capacity(properties.len());
        for p in properties {
            match store.token_id(Namespace::PropKey, p) {
                Some(t) => prop_tokens.push(t),
                None => return false,
            }
        }
        store.constraints().into_iter().any(|(_n, entry)| {
            entry.label_token == covering_token
                && entry.property_tokens == prop_tokens
                && entry.kind == kind
                && entry.type_descriptor.as_ref() == type_descriptor
        })
    }

    /// Refuses a `CREATE CONSTRAINT` while any other transaction holds **uncommitted writes**
    /// (`rmp` task #902) — the fail-closed answer to "a write I cannot see could falsify the
    /// assertion I am about to publish".
    ///
    /// # What `rmp` task #903 replaced, and what this still covers
    ///
    /// Task #903 made the DDL a first-class SSI transaction: it reads through its own [`Snapshot`] and
    /// announces a predicate footprint — the coarse token marker
    /// ([`note_constraint_token_read`](Self::note_constraint_token_read)) together with one precise
    /// per-value marker ([`note_constraint_value_read`](Self::note_constraint_value_read)) for every
    /// value it inspects — so a transaction that writes
    /// inside that footprint closes an rw-edge into the DDL and is aborted by the pivot rule. That
    /// closes the window this guard never could — the *declare-while-open* window, where nothing is
    /// uncommitted when the DDL runs but an already-open transaction later writes a duplicate its own
    /// snapshot hides from it (guarded by the DST scenario
    /// `graphus_dst::isolation` `constraint_declared_while_an_older_reader_is_open_903`).
    ///
    /// It does **not** subsume this guard, and the reason is a property of predicates rather than an
    /// omission. An rw-edge needs *both* endpoints to have announced something that matches. A
    /// transaction holding an uncommitted write that would falsify the constraint may have announced
    /// **nothing the DDL can pair with**, in three verified ways:
    ///
    /// 1. **A blind write announces no read.** `CREATE (:P {email: 'a'})` in a transaction opened
    ///    *before* the constraint existed performs no duplicate check — there was no constraint to
    ///    enforce — so it registers no SIREAD marker at all. The DDL's own marker gives `DDL --rw--> W`,
    ///    but a single rw-edge is not a dangerous structure and nothing aborts. Closing it would need
    ///    the *writer* to have read something the DDL wrote, i.e. every write to announce a predicate
    ///    read over the schema of the labels/properties it touches. That is a new
    ///    [`PredicateRead`] variant on the hot write path and a change to the whole engine's abort
    ///    profile — an architecture decision, deliberately not taken here.
    /// 2. **A relationship property write is gated on the schema already existing.**
    ///    `RecordStoreGraph::note_rel_property_predicate_write` (the `SET r.p = v` form) announces its
    ///    `RelEquality` marker only when `IndexSet::rel_equality_marker_possible` holds for
    ///    `(type, property)` — which, for the very constraint being declared, it does not yet. So an
    ///    in-flight `SET r.p = v` announces no marker the DDL's walk can pair with, whichever marker the
    ///    DDL holds.
    /// 3. **Not every store writer is SSI-tracked.** [`TxnCoordinator::raw_txn`](Self::raw_txn) — the
    ///    bulk-ingestion escape hatch — opens a transaction on the store alone, with no tracker entry
    ///    and no footprint. [`RecordStore::uncommitted_data_writer`] sees it; the tracker cannot.
    ///
    /// The guard is therefore kept **whole** rather than narrowed. Narrowing it to "refuse only when the
    /// DDL has an rw-edge to an uncommitted transaction" would look precise and would be wrong on all
    /// three counts above; narrowing it by guessing which entities an open writer might still touch is
    /// the unsound approximation the predicate footprint exists to remove. What did change is that it is
    /// no longer the *only* mechanism, and no longer the one the correctness of
    /// [`decided_value_for_key`](Self::decided_value_for_key) rests on.
    ///
    /// # Why a guard is required by the visibility discipline, not merely nice to have
    ///
    /// The walk judges the graph its snapshot sees (`rmp` tasks #902, #903). That is right, and on its
    /// own it is *strictly worse* than the raw read it replaced in one scenario: two committed nodes
    /// hold `'a'` and `'b'`, and a concurrent transaction `W` holds an uncommitted `SET b.email = 'a'`.
    /// Reading raw, the DDL saw `W`'s dirty `'a'` and refused — conservative, but safe. Reading through
    /// a snapshot, it sees no duplicate and ACCEPTS; `W` then commits two `'a'`s under a live
    /// `IS UNIQUE`, with no dangerous structure to abort anything (case 1 above) and no re-check
    /// anywhere to catch it. A constraint that is already false when it is published is unrepairable:
    /// the write path only ever checks *new* writes.
    ///
    /// # Why refuse rather than wait
    ///
    /// Every reference implementation excludes concurrent writers around this decision instead of
    /// guessing: PostgreSQL's non-concurrent build takes a `ShareLock` on the table and, if it still
    /// meets a tuple written by an unresolved transaction during a **unique** build, blocks on that
    /// transaction's XID and re-classifies it (`heapam_handler.c`,
    /// `XactLockTableWait` + `goto recheck`); Memgraph requires READ_ONLY/UNIQUE storage access, which
    /// waits until no writer is open; Neo4j re-acquires the exclusive LABEL lock before validating,
    /// which every property/label writer holds shared for its whole transaction
    /// (`ConstraintIndexCreator.java`). Graphus cannot *block*: the writer engine is single-threaded per
    /// database, so waiting for the open writer on the engine thread would deadlock — the writer needs
    /// that same thread to commit. Refusing with a **retryable** error is the same decision made
    /// non-blocking: the client retries, which is a client-side `XactLockTableWait`.
    ///
    /// # Scope
    ///
    /// It is bounded in one direction only: a transaction that has written **nothing** cannot make the
    /// data ambiguous, so open *readers* never refuse a DDL
    /// ([`RecordStore::uncommitted_data_writer`](graphus_storage::RecordStore::uncommitted_data_writer)).
    /// A transaction holding only pending **catalog** DDL is likewise out of scope, deliberately: it has
    /// mutated no node, relationship or property record, so the data this walk reads is unaffected by
    /// whether it commits.
    ///
    /// It runs **before** [`begin_schema_txn`](Self::begin_schema_txn), so the DDL's own transaction —
    /// which does become an uncommitted writer the moment it interns a token — is never its own blocker.
    /// Keeping that order is load-bearing; moving the call below the `begin` makes every
    /// `CREATE CONSTRAINT` refuse itself.
    ///
    /// This is sound only because no *new* write can appear while the DDL runs: the engine is
    /// single-threaded per database, so the whole validate-persist-register sequence is atomic with
    /// respect to every other writer, and off-thread reader-pool transactions never write.
    ///
    /// `DROP CONSTRAINT` is deliberately NOT guarded: dropping decides nothing about existing data, so
    /// no reading of it can be stale.
    ///
    /// # Availability
    ///
    /// A refusal is retryable but not queued — unlike PostgreSQL's `XactLockTableWait`, which gets in
    /// line, this fails fast and needs an instant with no open writer. Two things bound that: the DDL
    /// is one command on a single-threaded engine (so "no open writer" is a real, frequent state rather
    /// than a race to win), and a forgotten open transaction cannot block it forever, because the
    /// server reaps transactions past the configured maximum age
    /// ([`aged_transactions`](Self::aged_transactions), `rmp` #477). A sustained write stream can still
    /// starve a schema change: a principal with only `Write` privilege can, without holding any schema
    /// privilege, delay one with `Schema`. Removing that residual availability cost means removing the
    /// guard, which means adopting one of the two designs case 1 above rules out of this task's scope.
    ///
    /// # Errors
    /// Returns a retryable [`GraphusError::Transaction`] naming the constraint and the blocking
    /// transaction. The caller has made no change at this point, so a refusal has zero side effects.
    fn refuse_constraint_ddl_while_writers_open(&self, name: &str) -> Result<()> {
        match self.store.borrow().uncommitted_data_writer() {
            None => Ok(()),
            Some(writer) => Err(GraphusError::Transaction(format!(
                "constraint `{name}` cannot be validated while transaction {} holds uncommitted \
                 writes; retry once it commits or rolls back",
                writer.0
            ))),
        }
    }

    /// Declares a **constraint** named `name` over `(label, property)` of `kind`, **validating it
    /// against existing data first** and only then **durably recording it** (`rmp` task #99) — the
    /// constraint analogue of [`create_point_index`](Self::create_point_index), but synchronous and
    /// validated (a constraint has no `Populating` phase — it is in force the instant it is created).
    ///
    /// Order of operations (so a rejected creation has **zero** side effects):
    ///
    /// 0. **Refuse** outright if any other transaction holds uncommitted writes (`rmp` task #902) —
    ///    a write the walk cannot see could falsify the assertion it is about to publish, and not every
    ///    such write is expressible as a predicate
    ///    ([`refuse_constraint_ddl_while_writers_open`](Self::refuse_constraint_ddl_while_writers_open)).
    /// 1. **Open** a first-class serializable transaction
    ///    ([`begin_schema_txn`](Self::begin_schema_txn), `rmp` task #903) and **intern** the label +
    ///    property-key tokens in it.
    /// 2. **Validate** every node carrying the label that this transaction's snapshot sees, against the
    ///    rule ([`validate_existing_against_constraint`](Self::validate_existing_against_constraint)):
    ///    a uniqueness constraint rejects if two nodes share a value; an existence constraint rejects
    ///    if a node lacks the property. The walk announces the transaction's SSI predicate footprint as
    ///    it goes, so a concurrent transaction that later writes inside it aborts on the dangerous
    ///    structure. On any violation the transaction is **rolled back** (no token, no catalog entry,
    ///    no registration) and a [`ConstraintViolation`] runtime error is returned.
    /// 3. **Persist** the catalog entry, **register** the in-memory rule, and — for a uniqueness
    ///    constraint — **register + populate** the backing node-property index, all in the committed
    ///    transaction. After commit the durable catalog and the in-memory set agree, and the write
    ///    path enforces the rule.
    ///
    /// Re-declaring an existing name **replaces** it (re-validated against current data).
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped [`GraphusError::Runtime`] if existing data violates
    /// the constraint, a retryable [`GraphusError::Transaction`] if another transaction holds
    /// uncommitted writes (or, in principle, if the DDL's own transaction loses an SSI validation), or
    /// a storage error if interning a token, recording the catalog entry, or the committing transaction
    /// fails. On any error the constraint is left undeclared.
    pub fn create_constraint(
        &self,
        name: &str,
        label: &str,
        property: &str,
        kind: ConstraintKind,
    ) -> Result<()> {
        // The single-property convenience entry point (uniqueness / existence / property-type): forward
        // to the general composite-aware path with one property and no declared type.
        self.create_constraint_general(name, label, &[property], kind, None)
    }

    /// Declares a constraint over a (possibly composite) property tuple, validating existing data and
    /// durably recording it (`rmp` tasks #99, #100). The general form behind
    /// [`create_constraint`](Self::create_constraint) (single-property) and the NODE KEY / PROPERTY
    /// TYPE engine paths:
    ///
    /// - `properties` is the covered tuple in declared order — one property for `Unique` / `Existence`
    ///   / `PropertyType`, one-or-more for a composite `NodeKey`.
    /// - `type_descriptor` is the declared value type of a `PropertyType` constraint (`None` for every
    ///   other kind).
    ///
    /// The order of operations is identical to the single-property path (intern → validate existing →
    /// persist + register), so a rejected creation has **zero** side effects. For a `Unique` constraint
    /// a backing node-property index is registered + populated; for a `NodeKey` a backing **composite**
    /// index over the whole tuple is registered + populated (the composite analogue), so the write-time
    /// duplicate check is index-accelerated.
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped runtime error if existing data violates the
    /// constraint, or a storage error if interning a token, recording the entry, or committing fails.
    /// On any error the constraint is left undeclared.
    pub fn create_constraint_general(
        &self,
        name: &str,
        label: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
    ) -> Result<()> {
        self.create_constraint_general_cancellable(
            name,
            label,
            properties,
            kind,
            type_descriptor,
            &CancellationToken::new(),
        )
    }

    /// [`create_constraint_general`](Self::create_constraint_general) with a **cancellation token**
    /// the validation walk polls once per entity, so an operator can abort a long-running
    /// `CREATE CONSTRAINT` with `TERMINATE TRANSACTIONS` (`rmp` task #903).
    ///
    /// # The cancellation window ends at the point of no return
    ///
    /// The token is polled during token interning and the validation walk, and **not** afterwards. The
    /// remainder — persist the catalogue entry, commit, register the in-memory rule, rebuild the
    /// backing index — is the atomic tail that publishes the constraint, and it is deliberately
    /// uninterruptible: aborting inside it is what would produce a half-applied constraint (a durable
    /// catalogue entry with no in-memory rule, or a rule with no backing index). Everything before it
    /// is undone by one `rollback`, so a cancelled DDL is byte-for-byte the state a **refused** one
    /// leaves: no token committed, no catalogue entry, no in-memory registration, no index rebuild, and
    /// no leaked entry in the active set or the SSI tracker.
    ///
    /// This is why the walk — not the caller — owns the poll. The DDL is one synchronous command on a
    /// single-threaded engine, so there is no other moment at which anything could observe the request
    /// and stop it: without a poll inside the loop, a `TERMINATE TRANSACTIONS` against a
    /// `CREATE CONSTRAINT` over a large label could only ever be noticed after the walk had already
    /// finished, which is precisely when it no longer matters.
    ///
    /// # Errors
    /// As [`create_constraint_general`](Self::create_constraint_general), plus a
    /// [`GraphusError::Transaction`] naming the constraint when the token is cancelled.
    pub fn create_constraint_general_cancellable(
        &self,
        name: &str,
        label: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        debug_assert!(
            !properties.is_empty(),
            "a constraint covers at least one property"
        );
        // Names are globally unique across every schema catalog (`rmp` task #624): reject a name already
        // used by a *different* catalog (a re-declare within the constraint catalog keeps its semantics).
        // Checked BEFORE the concurrency guard below so a permanent error is reported as one, rather
        // than as a condition a retry could clear.
        if Self::name_used_by_other_catalog(self.store.borrow(), name, NameCatalog::Constraint) {
            return Err(index_name_in_use(name));
        }
        // Never decide a constraint on data that is not yet decided (`rmp` task #902). Re-checked here
        // and not only in `create_constraint_ddl`, because this is a public entry point in its own right.
        // Runs BEFORE the `begin` below, so the DDL's own transaction is not its own blocker.
        self.refuse_constraint_ddl_while_writers_open(name)?;
        // Pre-flight cancellation check (`rmp` task #903): a DDL terminated while it was still queued
        // behind another command on the engine's channel must not open a transaction at all. The walk
        // polls again per entity; this one keeps the "already cancelled" case free of any side effect
        // whatsoever, not merely of a rolled-back one.
        Self::check_constraint_ddl_cancelled(name, cancel)?;
        let (txn, snapshot) = self.begin_schema_txn();

        // Intern the covering token — a node **label** for the node kinds, a relationship **type** for
        // the `Rel*` kinds (`rmp` #638) — plus every property-key token (rolled back with the
        // transaction on any failure).
        let covering_ns = if kind.is_relationship() {
            Namespace::RelType
        } else {
            Namespace::Label
        };
        let intern = (|| -> Result<(u32, Vec<u32>)> {
            let store = self.store.borrow_mut();
            let label_token = store.intern_token(covering_ns, label)?;
            let mut prop_keys = Vec::with_capacity(properties.len());
            for property in properties {
                prop_keys.push(store.intern_token(Namespace::PropKey, property)?);
            }
            Ok((label_token, prop_keys))
        })();
        let (label_token, prop_keys) = match intern {
            Ok(v) => v,
            Err(e) => {
                let _ = self.rollback(txn);
                return Err(e);
            }
        };
        // The covering token is only known after interning, so the walk context is built here.
        let ctx = ConstraintWalkCtx {
            snapshot,
            kind,
            token: label_token,
            cancel,
        };

        // Validate existing data BEFORE recording anything. A violation rolls back the whole
        // transaction (so the interned tokens never become durable for a rejected create) and reports
        // the offending entity precisely. Relationship constraints scan relationships of the type; node
        // constraints scan nodes carrying the label. Both walks read through `ctx.snapshot` and announce
        // this transaction's SSI predicate footprint (`rmp` task #903).
        let validation = if kind.is_relationship() {
            self.validate_existing_rels_against_constraint(
                name,
                label,
                properties,
                label_token,
                &prop_keys,
                kind,
                type_descriptor.as_ref(),
                ctx,
            )
        } else {
            self.validate_existing_against_constraint(
                name,
                label,
                properties,
                label_token,
                &prop_keys,
                kind,
                type_descriptor.as_ref(),
                ctx,
            )
        };
        if let Err(e) = validation {
            let _ = self.rollback(txn);
            return Err(e);
        }

        // Conforming: record the durable catalog entry and commit (tokens + entry atomically).
        self.store.borrow_mut().set_constraint(
            txn,
            name.to_owned(),
            ConstraintEntry {
                label_token,
                property_tokens: prop_keys.clone(),
                kind,
                type_descriptor: type_descriptor.clone(),
            },
        );
        // Committed through the coordinator (`rmp` task #903), not `store.commit`: this runs the SSI
        // pivot check, records the commit timestamp in the tracker — which is what keeps the walk's
        // predicate markers live for later concurrent writers to conflict with — releases the lock
        // table, and retires the active-set entry. On an SSI abort the transaction is already rolled
        // back by `commit` itself, so the constraint is simply not declared.
        self.commit(txn)?;

        // Register the rule in the in-memory set so the write path enforces it from now on. A uniqueness
        // constraint registers + populates a backing node-property index; a node-key constraint
        // registers + populates a backing COMPOSITE index over the whole tuple — both make the write-time
        // duplicate check index-backed (a full rebuild repopulates them from the store). Existence and
        // property-type need no backing index (they are pure per-node predicates).
        let needs_rebuild = {
            // ### A ~60-line index borrow, and why it is sound (`rmp` #1010)
            //
            // Every call inside this block is `idx.*`, i.e. an inherent `IndexSet` method reached
            // through this one guard; nothing re-acquires `index`, and nothing touches `store`. The
            // block is deliberately closed before `Self::rebuild_index(&self.store, &self.index)` below,
            // which acquires **both** cells itself and would re-enter this one if the guard were still
            // alive — so the `needs_rebuild` binding is not a stylistic choice, it is what keeps the
            // rebuild outside the borrow.
            //
            // A note on the audit trail: this site was flagged as "crossing `scan_rel_ids`". It does
            // not. `scan_rel_ids` appears only in the `RelKey` arm's *comment*, where it records the
            // `rmp` #683 defect (an arity-1 REL KEY that registered no index fell through to a full
            // relationship scan). No scan is called from inside this borrow.
            let mut idx = self.index.borrow_mut();
            idx.register_constraint(name, label_token, prop_keys.clone(), kind, type_descriptor);
            match kind {
                ConstraintKind::Unique => {
                    match prop_keys.as_slice() {
                        [prop_key] => idx.register_node_property_with_state(
                            label_token,
                            *prop_key,
                            IndexState::Online,
                        ),
                        // Composite uniqueness (`rmp` #651) is backed by a composite index over the
                        // whole tuple — exactly like a node key — so the write-time duplicate check is
                        // index-accelerated and its SSI predicate footprint matches the key path.
                        _ => idx.register_composite(label_token, prop_keys.clone()),
                    }
                    true
                }
                ConstraintKind::NodeKey => {
                    idx.register_composite(label_token, prop_keys.clone());
                    true
                }
                ConstraintKind::RelUnique => {
                    // A relationship uniqueness constraint (`rmp` #638) registers + populates a backing
                    // relationship-property index on its single `(type, property)` (`rmp` task #646), so
                    // the write-time duplicate check is index-accelerated (a full rebuild repopulates it).
                    match prop_keys.as_slice() {
                        [prop_key] => idx.register_rel_property_with_state(
                            label_token,
                            *prop_key,
                            IndexState::Online,
                        ),
                        // Composite relationship uniqueness (`rmp` #651) is backed by a composite
                        // relationship index over the whole tuple — exactly like the RELATIONSHIP KEY
                        // below, and mirroring the node `Unique` arity>1 case above (`rmp` #683).
                        _ => idx.register_rel_composite(label_token, prop_keys.clone()),
                    }
                    true
                }
                ConstraintKind::RelKey => {
                    // A RELATIONSHIP KEY registers + populates a backing COMPOSITE relationship index
                    // over its whole tuple, at EVERY arity (`rmp` #683), mirroring `NodeKey` above.
                    //
                    // Arity is deliberately NOT special-cased down to a single-property relationship
                    // index: `enforce_constraints_for_rel` dispatches `RelKey` on KIND, not arity, so an
                    // arity-1 REL KEY routes to `rel_key_tuple_conflict` just like an arity-3 one. That
                    // is precisely the #683 defect — before this, an arity-1 REL KEY on `TRANSFER.tx_id`
                    // registered NO index at all and fell through to `scan_rel_ids()`, re-reading EVERY
                    // live relationship in the graph (measured: p50 12ms -> 474ms from 1e3 to 1e5 live
                    // rels, against a flat 5ms without the constraint).
                    idx.register_rel_composite(label_token, prop_keys.clone());
                    true
                }
                // Existence + property-type are pure per-entity predicates; RelPropertyType is a pure
                // per-relationship predicate. None of these need a backing index or a rebuild.
                ConstraintKind::Existence
                | ConstraintKind::PropertyType
                | ConstraintKind::RelExistence
                | ConstraintKind::RelPropertyType => false,
            }
        };
        if needs_rebuild {
            Self::rebuild_index(&self.store, &self.index);
        }
        Ok(())
    }

    /// Opens the **first-class** transaction a validating schema DDL runs in (`rmp` task #903),
    /// returning it together with its [`Snapshot`].
    ///
    /// # Why the constraint DDL stopped opening a bare transaction
    ///
    /// Every other schema DDL opens its transaction straight on the store — `next_txn_id += 1` then
    /// [`RecordStore::begin`] — which is adequate for a command that *decides nothing about data*: an
    /// index declaration, a drop, a build-chunk promotion. `CREATE CONSTRAINT` is the one schema command
    /// that reads the whole graph and publishes a durable assertion about it, and a bare transaction is
    /// registered in **neither** [`SsiTracker`] **nor** the active set, so it formed no rw-edge with
    /// anything and pinned no watermark. That is what let a transaction whose snapshot predates the
    /// constraint write a duplicate the constraint forbids, and commit it: nothing connected the two.
    ///
    /// Going through [`begin_serializable`](Self::begin_serializable) gives the DDL the three properties
    /// it was missing:
    ///
    /// 1. an [`SsiTracker`] registration, without which `record_predicate_read` leaves an entry no
    ///    `forget` can ever clean and `are_concurrent` returns `false` for it — so every marker it
    ///    announced would be silently inert;
    /// 2. an active-set entry, hence a real [`Snapshot`] to read through and a contribution to
    ///    [`oldest_active_snapshot`](Self::oldest_active_snapshot), so GC cannot reclaim a version the
    ///    walk is still reading;
    /// 3. commit / rollback through [`commit`](Self::commit) and [`rollback`](Self::rollback), which
    ///    run SSI validation and release the SSI entry and the active-set slot under a
    ///    drop guard (`rmp` #415) instead of leaking them.
    ///
    /// The DDL cannot be *spuriously* aborted by (3): it announces no predicate write and takes no
    /// physical write marker, so [`SsiTracker::detect_pivot_abort`]'s read-only exemption
    /// (`writes.is_empty() && !out_conflict`) applies unless a concurrent writer wrote inside its
    /// footprint — and while it validates there is none, because
    /// [`refuse_constraint_ddl_while_writers_open`](Self::refuse_constraint_ddl_while_writers_open) ran
    /// first and no writer can start mid-DDL on a single-threaded engine.
    fn begin_schema_txn(&self) -> (TxnId, Snapshot) {
        let txn = self.begin_serializable();
        // `begin_serializable` has just inserted the entry; the fallback reconstructs the identical
        // snapshot `begin_inner` builds rather than panicking on an invariant this method owns.
        let snapshot = self
            .with_active(|a| a.get(&txn).map(|t| t.snapshot))
            .unwrap_or_else(|| Snapshot::new(txn, self.store.borrow().snapshot_ts()));
        (txn, snapshot)
    }

    /// The error a cancelled constraint-DDL walk aborts with (`rmp` task #903), or [`Ok`] while the
    /// token is clear.
    ///
    /// Classified as a [`GraphusError::Transaction`] rather than a runtime error because that is what
    /// it is: the transaction was ended by an operator, the schema is unchanged, and re-issuing the
    /// statement is the correct client response. The server seam replaces the message with the
    /// registry's own `TERMINATE TRANSACTIONS` wording once it has confirmed the cancellation came from
    /// there rather than from a statement deadline.
    ///
    /// # Errors
    /// Returns the abort error when `cancel` is cancelled — either explicitly flagged, or past the
    /// deadline the token carries.
    fn check_constraint_ddl_cancelled(name: &str, cancel: &CancellationToken) -> Result<()> {
        if cancel.is_cancelled() {
            return Err(GraphusError::Transaction(format!(
                "constraint `{name}` was cancelled while it validated existing data; nothing was \
                 changed"
            )));
        }
        Ok(())
    }

    /// Announces the constraint-DDL transaction's **coarse** predicate SIREAD marker (`rmp` task #903):
    /// [`PredicateRead::Label`] for a node constraint, [`PredicateRead::RelType`] for a relationship
    /// one. Registered once, before the walk, because the walk's question is universally quantified
    /// over the token ("no node carrying `L` violates this rule"), so *any* concurrent write that makes
    /// an entity carry the token is a phantom for it.
    ///
    /// This is the marker that pairs with the write footprint every node create/update/delete announces
    /// (`RecordStoreGraph::note_predicate_write` pushes `Label(l)` for each of the node's labels) and
    /// with the `[AnyRel, RelType]` pair `create_rel` / `delete_rel` announce. It is deliberately coarse
    /// for the same reason the composite seek's marker is (`record_graph.rs`,
    /// `composite_seek_eq`): a coarse `Label` only adds an rw-edge between the DDL and concurrent
    /// same-token writers, which is exactly the population the DDL's decision depends on.
    fn note_constraint_token_read(&self, ctx: ConstraintWalkCtx<'_>) {
        let marker = if ctx.kind.is_relationship() {
            PredicateRead::RelType(ctx.token)
        } else {
            PredicateRead::Label(ctx.token)
        };
        self.ssi
            .borrow_mut()
            .record_predicate_read(ctx.snapshot.owner, marker);
    }

    /// Announces the **precise** per-value predicate SIREAD marker for one value the walk inspected
    /// (`rmp` task #903): [`PredicateRead::Equality`] for a node constraint,
    /// [`PredicateRead::RelEquality`] for a relationship one.
    ///
    /// # Why this is not redundant with the coarse marker
    ///
    /// For **nodes** it is, as far as edge formation goes: `RecordStoreGraph::note_predicate_write` is
    /// the single announcement point for every node create/update/delete, and it pushes `Label(l)`
    /// alongside its `Equality{l, p, v}` markers, so the coarse marker already forms every edge this
    /// one would. It is registered anyway, for symmetry with the relationship path and because it is
    /// the marker a *future* narrowing of the coarse footprint would keep.
    ///
    /// For **relationships** it is load-bearing and the coarse marker is not enough:
    /// `RecordStoreGraph::note_rel_property_predicate_write` — the `SET r.p = v` form — announces
    /// **only** the `RelEquality{T, p, v}` marker for the key it changed, never the `[AnyRel, RelType]`
    /// pair that `create_rel` announces. A relationship uniqueness/key constraint whose DDL held only
    /// `RelType(T)` therefore forms no edge at all with a concurrent `SET` on an existing relationship
    /// of that type — precisely the write that can duplicate a covered value. Measured, by disabling
    /// this method and re-running the DST scenario
    /// `graphus_dst::isolation` `relationship_constraint_vs_a_concurrent_property_update_903`: with the
    /// value markers the concurrent writer is aborted and one live `'a'` remains; with only the coarse
    /// marker it commits, leaving two committed `'a'`s under a live relationship `IS UNIQUE`.
    ///
    /// # Cost
    ///
    /// One marker per inspected value, so O(entities carrying the token) markers held until the DDL is
    /// pruned from the tracker. That is the same order as the walk's own [`SeenTuples`] set, which
    /// already retains every value for the duplicate search, so it does not change the memory profile
    /// of a `CREATE CONSTRAINT`.
    ///
    /// # Encoding
    ///
    /// [`encode_equality_canonical`], never `encode_single`: the order-preserving index key tags
    /// `Integer(1)` and `Float(1.0)` apart, so a writer of `1.0` and a DDL that read `1` would register
    /// different markers and the rw-edge would silently never close (`rmp` #171 blocker C1). A value
    /// that does not encode canonically (`Null` / `List` / `Map` / `NaN`) contributes no marker, which
    /// is sound: no writer can announce one for it either, and the coarse token marker still covers
    /// every node write and every relationship create/delete.
    fn note_constraint_value_read(&self, ctx: ConstraintWalkCtx<'_>, prop_key: u32, value: &Value) {
        let Ok(encoded) = encode_equality_canonical(value) else {
            return; // not canonically encodable: no writer can hold a matching marker either
        };
        let marker = if ctx.kind.is_relationship() {
            PredicateRead::RelEquality {
                rel_type: ctx.token,
                property: prop_key,
                value: encoded,
            }
        } else {
            PredicateRead::Equality {
                label: ctx.token,
                property: prop_key,
                value: encoded,
            }
        };
        self.ssi
            .borrow_mut()
            .record_predicate_read(ctx.snapshot.owner, marker);
    }

    /// The value node `id` holds for `prop_key` as of the walk's snapshot, **announcing** the precise
    /// predicate SIREAD marker for it (`rmp` task #903) — the marker-registering wrapper the constraint
    /// walk uses in place of the bare [`node_value_for_key`](Self::node_value_for_key), so that every
    /// value the decision rests on leaves a footprint.
    ///
    /// # Errors
    /// Propagates a store read fault, exactly as [`node_value_for_key`](Self::node_value_for_key) does.
    fn constraint_node_value(
        &self,
        id: u64,
        prop_key: u32,
        ctx: ConstraintWalkCtx<'_>,
    ) -> Result<Option<Value>> {
        let value = self.node_value_for_key(id, prop_key, ctx.snapshot)?;
        if let Some(v) = &value {
            self.note_constraint_value_read(ctx, prop_key, v);
        }
        Ok(value)
    }

    /// The relationship analogue of [`constraint_node_value`](Self::constraint_node_value)
    /// (`rmp` task #903).
    ///
    /// # Errors
    /// Propagates a store read fault, exactly as [`rel_value_for_key`](Self::rel_value_for_key) does.
    fn constraint_rel_value(
        &self,
        id: u64,
        prop_key: u32,
        ctx: ConstraintWalkCtx<'_>,
    ) -> Result<Option<Value>> {
        let value = self.rel_value_for_key(id, prop_key, ctx.snapshot)?;
        if let Some(v) = &value {
            self.note_constraint_value_read(ctx, prop_key, v);
        }
        Ok(value)
    }

    /// Scans every node visible to `ctx`'s snapshot carrying `label_token` and rejects if any violates
    /// the constraint of `kind` on `prop_key` (`rmp` task #99). Used by
    /// [`create_constraint`](Self::create_constraint) to refuse a constraint that existing data does
    /// not satisfy. No-op success when no node carries the label.
    ///
    /// # The scan is physical; the decision must not be
    ///
    /// [`scan_node_ids`](graphus_storage::RecordStore::scan_node_ids) enumerates every **slot-occupied**
    /// node, which includes MVCC tombstones the GC has not reclaimed — and GC has no automatic trigger
    /// (`rmp` #305), so "not yet" can mean "never". A node the DDL's snapshot cannot see is therefore
    /// filtered out here ([`visible_to`](Self::visible_to)), and each surviving node's property values
    /// are resolved through the same snapshot by
    /// [`node_value_for_key`](Self::node_value_for_key). Before `rmp` task #902 neither filter existed,
    /// so a constraint the live data satisfies was refused over data no query can reach; `rmp` task #903
    /// then replaced the raw stamp tests with the production [`is_visible_via`] predicate.
    ///
    /// This is the exact opposite polarity to an index *population*, which may legitimately read raw
    /// (`rmp` #765/#766/#771): a candidate index is a superset whose seek re-checks visibility, whereas
    /// a constraint decision is final and is never re-checked. The same reading is right there and
    /// wrong here.
    ///
    /// # The walk leaves an SSI footprint (`rmp` task #903)
    ///
    /// It announces the coarse token marker once ([`note_constraint_token_read`](Self::note_constraint_token_read))
    /// and one precise equality marker per value it inspects
    /// ([`note_constraint_value_read`](Self::note_constraint_value_read)), so a transaction that later
    /// writes inside the footprint — including one whose snapshot predates the constraint and so cannot
    /// itself see the row that makes its write a duplicate — closes an rw-edge into the DDL and is
    /// aborted by the pivot rule instead of committing a violation.
    ///
    /// # Cost, and why it is an availability property (`rmp` task #956)
    ///
    /// One store read and one property-chain resolution per node carrying the label, plus — for the
    /// uniqueness kinds — an O(1) expected duplicate probe against [`SeenTuples`]. The probe used to be
    /// a linear scan of every value already inspected, making the walk quadratic in the covered
    /// entities. Because the walk holds this transaction's snapshot from `begin` to `commit`
    /// (`rmp` task #903), its duration *is* the window in which it pins the GC watermark, so a
    /// quadratic walk suspended reclamation on a live database for a quadratic time.
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped runtime error naming the first offending node /
    /// duplicate value (uniqueness) or the first node missing the property (existence). A store-read
    /// fault on a node **fails the DDL** (`rmp` task #733) — see the guard on the label read below.
    #[allow(clippy::too_many_arguments)]
    fn validate_existing_against_constraint(
        &self,
        name: &str,
        label: &str,
        properties: &[&str],
        label_token: u32,
        prop_keys: &[u32],
        kind: ConstraintKind,
        type_descriptor: Option<&ConstraintTypeDescriptor>,
        ctx: ConstraintWalkCtx<'_>,
    ) -> Result<()> {
        self.note_constraint_token_read(ctx);
        let node_ids = self.store.borrow_mut().scan_node_ids()?;
        // The covered values seen so far, for the uniqueness kinds. One indexed set serves the
        // single-property and the composite kinds alike — a single-property value is simply a 1-tuple —
        // so the two can no longer drift apart, and neither is quadratic (`rmp` task #956).
        let mut seen = SeenTuples::new();
        for id in node_ids {
            // Cancellation is checked FIRST, before this node's record read (`rmp` task #903): the
            // check is one atomic load, the work it guards is a store read plus a property-chain walk,
            // and the walk is O(store) — so the poll must be inside the loop or an operator's
            // `TERMINATE TRANSACTIONS` can only ever be observed after the walk has finished.
            Self::check_constraint_ddl_cancelled(name, ctx.cancel)?;
            // A node the DDL's snapshot cannot see is not part of the graph the constraint governs
            // (`rmp` tasks #902, #903). The scan returns it because the record keeps its slot until GC
            // reclaims it, and GC has no automatic trigger (`rmp` #305), so judging it anyway refused a
            // valid constraint indefinitely. `rmp` task #902 filtered on a raw `expired_ts != 0`, sound
            // only under the "no writer is open" precondition; the walk now runs inside a real
            // transaction, so the filter is the production [`is_visible_via`] predicate and the decision is
            // made over exactly the node set a `MATCH` in this transaction would return. PostgreSQL
            // draws the same line in its index build: dead and recently-dead tuples may still be
            // *indexed* for older snapshots, but are always "excluded from unique-checking"
            // (`heapam_handler.c`, `HEAPTUPLE_RECENTLY_DEAD`).
            let rec = self.store.borrow().node(id)?;
            if !self.visible_to(ctx.snapshot, rec.mvcc.created_ts, rec.mvcc.expired_ts)? {
                continue;
            }
            // A node whose labels cannot be read **fails the DDL** (`rmp` task #733). This used to
            // `continue`, i.e. validate the constraint against the nodes it happened to be able to read
            // — so a `CREATE CONSTRAINT … IS UNIQUE` could be ACCEPTED over data that violates it, with
            // the duplicate hiding in the unreadable node. From that moment the constraint is a lie: the
            // catalog says the property is unique, queries and planners may rely on it, and the
            // offending row is already committed. Refusing is always safe for a DDL — the operator
            // retries once the store is readable — and it is the only answer that cannot corrupt the
            // schema's meaning. (This is the same class of defect `rmp` #733 exists to eliminate: never
            // publish a schema object you could not fully verify.)
            //
            // Decoded off the record just read, which is what `RecordStore::node_labels` does (it is a
            // one-line delegation to the same `labels::token_ids`, erroring identically on an
            // overflow-form bitmap) — so the whole per-node decision costs ONE record read rather than
            // two, on a walk that is already O(store).
            //
            // The label word is read IN PLACE, not resolved through the snapshot: labels are stored as
            // a bitmap on the record and are not versioned per snapshot (`rmp` #767), so unlike the
            // property chain there is no older version to fall back to. Reading the current word is
            // therefore correct here for the same reason it is correct for the DDL to run at all — the
            // `rmp` #902 guard means no other transaction holds an uncommitted label change while the
            // walk runs, and none can start mid-DDL on a single-threaded engine. If that guard is ever
            // lifted, this read needs `RecordStore::label_bitmap_at` (the `rmp` #767 as-of-snapshot
            // resolver the read path uses), not just the visibility filter above.
            let label_tokens =
                graphus_storage::labels::token_ids(rec.labels).map_err(GraphusError::from)?;
            if !label_tokens.contains(&label_token) {
                continue; // node does not carry the covered label
            }
            match kind {
                ConstraintKind::Existence => {
                    // A missing or null value violates the existence (NOT NULL) constraint.
                    let value = self.constraint_node_value(id, prop_keys[0], ctx)?;
                    if value.as_ref().is_none_or(graphus_core::Value::is_null) {
                        return Err(ConstraintViolation::Existence {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                        }
                        .into_error());
                    }
                }
                ConstraintKind::Unique if prop_keys.len() == 1 => {
                    // A null/absent value never participates in uniqueness (Cypher equality treats
                    // null as never-equal), matching the index's treatment.
                    let Some(value) = self
                        .constraint_node_value(id, prop_keys[0], ctx)?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    if seen.contains_equal(std::slice::from_ref(&value)) {
                        return Err(ConstraintViolation::Uniqueness {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                            value: render_value(&value),
                        }
                        .into_error());
                    }
                    seen.record(vec![value]);
                }
                ConstraintKind::Unique => {
                    // Composite uniqueness (`rmp` #651): no existence requirement — a null in any
                    // covered property relaxes uniqueness, so an incomplete tuple is skipped; the
                    // complete tuple must be unique across the scanned nodes.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .constraint_node_value(id, prop_key, ctx)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        continue;
                    }
                    if seen.contains_equal(&tuple) {
                        return Err(ConstraintViolation::UniquenessComposite {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen.record(tuple);
                }
                ConstraintKind::NodeKey => {
                    // Existence half: every covered property must be present and non-null.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .constraint_node_value(id, prop_key, ctx)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        return Err(ConstraintViolation::NodeKeyMissing {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                        }
                        .into_error());
                    }
                    // Uniqueness half: the complete tuple must not have been seen before.
                    if seen.contains_equal(&tuple) {
                        return Err(ConstraintViolation::NodeKeyDuplicate {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen.record(tuple);
                }
                ConstraintKind::PropertyType => {
                    // Only a present, non-null value is type-checked (a missing/null value is allowed —
                    // property-type does not imply existence).
                    let Some(value) = self
                        .constraint_node_value(id, prop_keys[0], ctx)?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    let descriptor = type_descriptor
                        .expect("INVARIANT: a PropertyType constraint always carries a descriptor");
                    if !crate::constraint::value_matches_descriptor(&value, descriptor) {
                        return Err(ConstraintViolation::PropertyType {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                            expected: crate::constraint::type_descriptor_name(descriptor),
                            actual: crate::constraint::value_type_name(&value),
                        }
                        .into_error());
                    }
                }
                // The relationship kinds are validated by `validate_existing_rels_against_constraint`;
                // the caller never routes them here, so treat them as "no node violation".
                ConstraintKind::RelUnique
                | ConstraintKind::RelExistence
                | ConstraintKind::RelKey
                | ConstraintKind::RelPropertyType => continue,
            }
        }
        Ok(())
    }

    /// The value node `id` holds for property-key token `prop_key` **as of `snapshot`**, or [`None`]
    /// if the node does not hold that property in that snapshot (`rmp` task #99). The value a
    /// constraint decision is made on, so it must be the value a `MATCH` in the same transaction would
    /// return — see [`decided_value_for_key`](Self::decided_value_for_key) for the resolution rule.
    ///
    /// The read is [`RecordStore::decision_scan_node_properties`], the **decision**-polarity member
    /// of the pair (`rmp` task #905): it cannot be called without the snapshot, and the
    /// [`DecidedProperties`] it returns cannot be built any other way. Reaching for the
    /// superset-polarity twin here is what `rmp` task #902 was.
    ///
    /// # Errors
    /// Propagates a store read fault. It is deliberately **fallible** (`rmp` task #733): it used to fold
    /// a read fault into `None`, indistinguishable from "the node has no such property" — which let the
    /// constraint-validation walk that calls it treat an unreadable node as *not* violating, and so
    /// accept a `IS UNIQUE` constraint whose duplicate was hiding in that node.
    fn node_value_for_key(
        &self,
        id: u64,
        prop_key: u32,
        snapshot: Snapshot,
    ) -> Result<Option<Value>> {
        let store = self.store.borrow();
        let decided = store.decision_scan_node_properties(id, snapshot)?;
        Self::decided_value_for_key(store, &decided, prop_key)
    }

    /// The value relationship `id` holds for property-key token `prop_key` as of `snapshot`
    /// (`rmp` #638), or [`None`] if it does not hold that property in that snapshot — the relationship
    /// analogue of [`node_value_for_key`](Self::node_value_for_key), reading through the same
    /// decision-polarity surface.
    ///
    /// # Errors
    /// Propagates a store read fault, for the reason documented on
    /// [`node_value_for_key`](Self::node_value_for_key) (`rmp` task #733).
    fn rel_value_for_key(
        &self,
        id: u64,
        prop_key: u32,
        snapshot: Snapshot,
    ) -> Result<Option<Value>> {
        let store = self.store.borrow();
        let decided = store.decision_scan_rel_properties(id, snapshot)?;
        Self::decided_value_for_key(store, &decided, prop_key)
    }

    /// Decodes the version of `prop_key` an already-narrowed [`DecidedProperties`] holds, or [`None`]
    /// when the entity does not hold that key in the snapshot it was narrowed against (`rmp` tasks
    /// #902, #903, #905).
    ///
    /// # Why the parameter is `DecidedProperties` and not a chain
    ///
    /// This helper used to take the entity's **raw** chain and resolve the key itself. The raw chain
    /// returns every `in_use` record, and a removed version keeps its slot until GC reclaims it — which
    /// has no automatic trigger (`rmp` #305) — so a caller who did not apply the visibility filter read
    /// a committed `REMOVE n.email` as a present value, and `CREATE CONSTRAINT … IS UNIQUE` was refused
    /// over a duplicate no `MATCH` can find. That was `rmp` task #902; `rmp` task #903 replaced its raw
    /// `expired_ts != 0` patch with the production [`is_visible_via`] predicate, and `rmp` task #905 moved
    /// the narrowing itself into [`SupersetProperties::decide`] so that **the resolution can no longer
    /// be skipped**: the only value of this parameter type is one a [`Snapshot`] produced.
    ///
    /// Exactly one version of a key is visible to a given snapshot (a `SET` stamps the new version's
    /// `xmin` and the old version's `xmax` with the same transaction), so the narrowing resolves a
    /// single value rather than choosing among several.
    ///
    /// # Errors
    /// Propagates a store read fault raised while decoding the value (an unreadable overflow chain).
    ///
    /// This decodes **only the covered key**, where the caller used to decode the entity's whole
    /// property chain. That deliberately narrows the `rmp` #733 fail-closed surface: an unreadable
    /// overflow chain belonging to an *unrelated* property no longer fails the DDL. Sound, because the
    /// constraint decision depends on no other property — and the fail-closed guarantee that matters is
    /// intact, since the chain walk itself still errors on a missing page or a malformed chain, and any
    /// fault on the covered value still propagates.
    fn decided_value_for_key(
        store: &RecordStore<D, S>,
        decided: &DecidedProperties,
        prop_key: u32,
    ) -> Result<Option<Value>> {
        let Some(prop) = decided.visible_version(prop_key) else {
            return Ok(None); // no version of this key is visible: the entity does not hold it
        };
        store
            .decode_property_value(prop.type_tag, prop.value_inline)
            .map(Some)
    }

    /// Whether the entity version carrying the MVCC stamps `created_ts` / `expired_ts` is visible to
    /// `snapshot` (`rmp` task #903) — the constraint walk's node/relationship filter, delegating to the
    /// one production visibility predicate [`is_visible_via`] so the walk judges exactly the graph a
    /// `MATCH` in the same transaction would.
    ///
    /// # Why this stays on the `New` polarity (`04 §5.1.4`, `rmp` #972)
    ///
    /// Every other read in the executor was refined to statement granularity; this one is deliberately
    /// **not**, and the difference is not an oversight.
    ///
    /// A constraint validation is not a query. It answers "does the state this transaction will
    /// commit satisfy the constraint?", and the state it will commit includes everything the current
    /// statement has just written. `Old` would hide precisely the rows the DDL is being asked to judge:
    /// `CREATE (:P {e:'x'}) CREATE (:P {e:'x'})` followed by a uniqueness check that could not see
    /// either node would accept a duplicate — a committed constraint violation, which is an ACID
    /// failure, not a visibility nuance.
    ///
    /// It is therefore also correct that this takes the header words alone rather than the
    /// chain-walking `entity_visible_at`: under `New` the two agree by construction, so consulting the
    /// chain would cost I/O to reach the same verdict.
    ///
    /// # Errors
    /// Propagates a stamp-resolution fault from the [`CommitOracle`] door (`rmp` #1069). A record
    /// whose visibility cannot be resolved **fails the DDL**, exactly as an unreadable label word
    /// does (`rmp` #733): a constraint accepted over data nobody could judge is a schema that lies.
    fn visible_to(&self, snapshot: Snapshot, created_ts: u64, expired_ts: u64) -> Result<bool> {
        let store = self.store.borrow();
        is_visible_via(
            &store.commit_registry_snapshot(),
            snapshot.with_view(graphus_txn::View::New),
            created_ts,
            expired_ts,
        )
    }

    /// Scans every relationship visible to `ctx`'s snapshot carrying the type token `type_token` and
    /// rejects if any violates the relationship constraint of `kind` on `prop_keys` (`rmp` #638) — the
    /// relationship analogue of
    /// [`validate_existing_against_constraint`](Self::validate_existing_against_constraint), including
    /// its snapshot discipline (`rmp` tasks #902/#903: invisible relationships are filtered out, values
    /// resolve newest-visible-wins) and its SSI footprint. Used by
    /// [`create_constraint_general`](Self::create_constraint_general) to refuse a relationship
    /// constraint that existing data does not satisfy. No-op success when no relationship carries the
    /// type. A relationship whose record cannot be read **fails the DDL** (`rmp` task #733).
    ///
    /// The per-value [`PredicateRead::RelEquality`] markers this walk announces are the load-bearing
    /// half of its footprint, not a refinement of the coarse one — see
    /// [`note_constraint_value_read`](Self::note_constraint_value_read) for why `RelType(T)` alone
    /// cannot pair with a concurrent `SET r.p = v`.
    ///
    /// Its duplicate probe is the same O(1)-expected [`SeenTuples`] set the node walk uses, for the
    /// reasons given there (`rmp` task #956).
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped runtime error (with `entity: Relationship`) naming the
    /// first offending relationship / duplicate value.
    #[allow(clippy::too_many_arguments)]
    fn validate_existing_rels_against_constraint(
        &self,
        name: &str,
        rel_type: &str,
        properties: &[&str],
        type_token: u32,
        prop_keys: &[u32],
        kind: ConstraintKind,
        type_descriptor: Option<&ConstraintTypeDescriptor>,
        ctx: ConstraintWalkCtx<'_>,
    ) -> Result<()> {
        self.note_constraint_token_read(ctx);
        let rel_ids = self.store.borrow().scan_rel_ids()?;
        // The covered values seen so far, for the uniqueness kinds — the relationship twin of the node
        // walk's set, and the same one indexed structure for the single-property and composite kinds
        // alike (`rmp` task #956).
        let mut seen = SeenTuples::new();
        for id in rel_ids {
            // Polled per relationship, for the reason given on the node walk (`rmp` task #903).
            Self::check_constraint_ddl_cancelled(name, ctx.cancel)?;
            // A relationship whose record cannot be read **fails the DDL** (`rmp` task #733) — the
            // relationship twin of the node guard above. Skipping it would let a `CREATE CONSTRAINT …
            // IS UNIQUE` be accepted over data that violates it, with the duplicate hiding in the
            // unreadable slot.
            let rec = self.store.borrow().rel(id)?;
            // A relationship the DDL's snapshot cannot see is not part of the graph the constraint
            // governs (`rmp` tasks #902, #903) — the relationship twin of the node visibility filter,
            // for the same reason and with the same soundness argument.
            if !self.visible_to(ctx.snapshot, rec.mvcc.created_ts, rec.mvcc.expired_ts)? {
                continue;
            }
            if rec.type_id != type_token {
                continue; // relationship does not carry the covered type
            }
            match kind {
                ConstraintKind::RelExistence => {
                    let value = self.constraint_rel_value(id, prop_keys[0], ctx)?;
                    if value.as_ref().is_none_or(graphus_core::Value::is_null) {
                        return Err(ConstraintViolation::Existence {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            property: properties[0].to_owned(),
                        }
                        .into_error());
                    }
                }
                ConstraintKind::RelUnique if prop_keys.len() == 1 => {
                    let Some(value) = self
                        .constraint_rel_value(id, prop_keys[0], ctx)?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    if seen.contains_equal(std::slice::from_ref(&value)) {
                        return Err(ConstraintViolation::Uniqueness {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            property: properties[0].to_owned(),
                            value: render_value(&value),
                        }
                        .into_error());
                    }
                    seen.record(vec![value]);
                }
                ConstraintKind::RelUnique => {
                    // Composite relationship uniqueness (`rmp` #651): no existence requirement — a null
                    // in any covered property relaxes uniqueness (skip an incomplete tuple); the
                    // complete tuple must be unique across the scanned relationships.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .constraint_rel_value(id, prop_key, ctx)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        continue;
                    }
                    if seen.contains_equal(&tuple) {
                        return Err(ConstraintViolation::UniquenessComposite {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen.record(tuple);
                }
                ConstraintKind::RelKey => {
                    // Existence half: every covered property must be present and non-null.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .constraint_rel_value(id, prop_key, ctx)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        return Err(ConstraintViolation::NodeKeyMissing {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                        }
                        .into_error());
                    }
                    // Uniqueness half: the complete tuple must not have been seen before.
                    if seen.contains_equal(&tuple) {
                        return Err(ConstraintViolation::NodeKeyDuplicate {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen.record(tuple);
                }
                ConstraintKind::RelPropertyType => {
                    let Some(value) = self
                        .constraint_rel_value(id, prop_keys[0], ctx)?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    let descriptor = type_descriptor
                        .expect("INVARIANT: a PropertyType constraint always carries a descriptor");
                    if !crate::constraint::value_matches_descriptor(&value, descriptor) {
                        return Err(ConstraintViolation::PropertyType {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            property: properties[0].to_owned(),
                            expected: crate::constraint::type_descriptor_name(descriptor),
                            actual: crate::constraint::value_type_name(&value),
                        }
                        .into_error());
                    }
                }
                // The node kinds are validated by `validate_existing_against_constraint`; the caller
                // never routes them here.
                ConstraintKind::Unique
                | ConstraintKind::Existence
                | ConstraintKind::NodeKey
                | ConstraintKind::PropertyType => continue,
            }
        }
        Ok(())
    }

    /// Drops the constraint named `name` (`rmp` tasks #99, #100): removes its durable catalog entry in
    /// a committed transaction and unregisters its in-memory rule, so the write path stops enforcing it.
    /// Idempotent on a never-declared name (a clean no-op success).
    ///
    /// The backing node-property index of a uniqueness constraint is **left registered** (a query may
    /// still benefit from it, and a plain `CREATE INDEX` may have independently declared it); only the
    /// constraint *rule* is removed. A node-key constraint's backing **composite** index, by contrast,
    /// exists only to serve the constraint (no `CREATE INDEX` surface declares one), so it is
    /// **unregistered** here to release its in-memory tree.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_constraint(&self, name: &str) -> Result<bool> {
        // Resolve the entry first so a node key's backing composite index can be unregistered by its
        // covered `(label, property tuple)` after the durable removal.
        let entry = self.store.borrow().constraint(name);
        let Some(entry) = entry else {
            // A no-op when the constraint is not declared (avoids an empty committed transaction).
            self.index.borrow_mut().unregister_constraint(name);
            return Ok(false); // nothing removed.
        };
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_constraint(txn, name);
        self.store.borrow_mut().commit(txn)?;
        // A node key's backing composite tree may be **shared** with a standalone composite index over
        // the same `(label, tuple)` (`rmp` task #657): keep it if such an index still needs it, so
        // dropping the constraint does not silently disable the standalone index's acceleration.
        let shared_with_composite_index = entry.kind == ConstraintKind::NodeKey
            && self
                .store
                .borrow()
                .composite_index_name_for(entry.label_token, &entry.property_tokens)
                .is_some();
        // The relationship twin (`rmp` #683): a RELATIONSHIP KEY / composite relationship-uniqueness
        // constraint's backing composite tree may likewise be **shared** with a standalone composite
        // relationship index over the same `(type, tuple)` (`rmp` #666), so keep it if one still needs
        // it — dropping the constraint must not silently disable the standalone index's acceleration.
        let rel_backed_by_composite = matches!(entry.kind, ConstraintKind::RelKey)
            || (entry.kind == ConstraintKind::RelUnique && entry.property_tokens.len() > 1);
        let rel_shared_with_composite_index = rel_backed_by_composite
            && self
                .store
                .borrow()
                .rel_composite_index_name_for(entry.label_token, &entry.property_tokens)
                .is_some();
        let mut idx = self.index.borrow_mut();
        idx.unregister_constraint(name);
        if entry.kind == ConstraintKind::NodeKey && !shared_with_composite_index {
            idx.unregister_composite(entry.label_token, &entry.property_tokens);
        }
        if rel_backed_by_composite && !rel_shared_with_composite_index {
            idx.unregister_rel_composite(entry.label_token, &entry.property_tokens);
        }
        Ok(true) // a constraint was removed.
    }

    /// Lists every declared constraint as a [`ConstraintInfo`] (`rmp` tasks #99, #100) for a
    /// `SHOW CONSTRAINTS` surface. Reads the durable catalog and resolves the tokens back to names; an
    /// entry whose tokens have no resolvable name (a defensively-skipped impossibility for a live token)
    /// is omitted. A node-key constraint reports its **whole** property tuple in declared order; a
    /// property-type constraint reports its declared type. Ordered by name.
    #[must_use]
    pub fn list_constraints(&self) -> Vec<ConstraintInfo> {
        let store = self.store.borrow();
        store
            .constraints()
            .into_iter()
            .filter_map(|(name, entry)| {
                // Resolve the covering token in its namespace — a relationship type for the `Rel*`
                // kinds (`rmp` #638), a node label otherwise.
                let covering_ns = constraint_covering_namespace(entry.kind);
                let label = store.token_name(covering_ns, entry.label_token)?;
                // Resolve every covered property token's name (one for non-composite kinds, the whole
                // tuple for a node key). A token with no resolvable name skips the whole entry.
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for &prop_token in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, prop_token)?.to_owned());
                }
                Some(ConstraintInfo {
                    name,
                    label: label.to_owned(),
                    properties,
                    kind: entry.kind,
                    type_descriptor: entry.type_descriptor,
                })
            })
            .collect()
    }

    /// Whether any non-blocking index build is still in progress (`rmp` task #91/#72/#98). The engine
    /// loop uses this to decide between a plain blocking receive (no builds) and a timed receive that
    /// also drives the build between commands.
    ///
    /// Deliberately does **not** include the degraded state (`rmp` task #733): callers such as
    /// `LocalEngine::drain_index_builds` spin `while has_pending_index_builds() { advance… }`, so
    /// reporting a permanently-faulting store as "pending" would hang them forever. Degradation is
    /// surfaced by [`indexes_degraded`](Self::indexes_degraded) and repaired by
    /// [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild), which is bounded and
    /// back-off-limited.
    #[must_use]
    pub fn has_pending_index_builds(&self) -> bool {
        let builds = self.builds();
        !builds.pending_builds.is_empty()
            || !builds.pending_fulltext_builds.is_empty()
            || !builds.pending_spatial_builds.is_empty()
            // A queued `db.resampleIndex` (`rmp` task #572) is pending index work too. Reporting it
            // here is what makes the drain UNMISSABLE: every existing driver — the server's
            // `drive_index_build` after each command, the DST `LocalEngine::drain_index_builds` spin —
            // already loops on this predicate, so none of them needs to know resamples exist. Were it
            // omitted, a resample would silently never run and the procedure would have lied.
            || self.index.borrow().has_pending_resamples()
    }

    /// Whether the **label (token LOOKUP) index** may still be used (`rmp` task #733).
    ///
    /// It is the base of every fallback in the engine — a declined seek degrades to a label scan — and a
    /// `fail_closed` leaves it empty, at which point the label-scan seam bypasses it and enumerates the
    /// store instead. `SHOW INDEXES` must therefore report the synthetic `LOOKUP` row as `POPULATING`
    /// rather than the hard-coded `ONLINE`: the index that stopped being usable is precisely the one the
    /// engine leans on hardest, and claiming it is online is the most misleading thing the surface could
    /// say.
    #[must_use]
    pub fn label_lookup_usable(&self) -> bool {
        self.index.borrow().labels_usable()
    }

    /// Whether the derived indexes are currently **degraded** — a storage fault made them
    /// untrustworthy and [`IndexSet::fail_closed`] dropped the engine to scans (`rmp` task #733).
    ///
    /// Answers are still **correct** while degraded (every read path is on the exact scan), but they are
    /// unaccelerated, and the condition must be visible: the server logs it, meters it, and reports the
    /// affected indexes as `POPULATING` rather than `ONLINE`.
    #[must_use]
    pub fn indexes_degraded(&self) -> bool {
        self.index.borrow().is_degraded()
    }

    /// How many VECTOR indexes are **currently** blocked by a `rmp` #780 build conflict, node and
    /// relationship together — i.e. how many k-NN surfaces are serving the exact brute-force scan.
    ///
    /// Answers stay **correct** while blocked (the scan is exact where the ANN is approximate), but
    /// they cost `O(covered entities x dim)` instead of a graph descent, and the index keeps reporting
    /// `ONLINE`. Exactly like [`indexes_degraded`](Self::indexes_degraded), the condition must be
    /// visible or it is indistinguishable from a healthy-but-slow engine.
    #[must_use]
    pub fn blocked_vector_indexes(&self) -> usize {
        self.index.borrow().blocked_vector_indexes()
    }

    /// Whether the cross-snapshot full-text/spatial marker is **poisoned** (`rmp` task #803) — i.e.
    /// whether every TEXT / FULLTEXT / SPATIAL seek in this database, node and relationship, inline and
    /// off-thread, is currently declining to the exact scan while `SHOW INDEXES` reports `ONLINE`.
    ///
    /// Answers stay correct and the state is self-repairing (see
    /// [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild)), but it must be visible:
    /// this is the fault class that reached production-example scale precisely because nothing reported
    /// it.
    #[must_use]
    pub fn ft_spatial_poisoned(&self) -> bool {
        self.index.borrow().ft_spatial_poisoned()
    }

    /// How many times the full-text/spatial marker has been poisoned over this coordinator's life
    /// (`rmp` task #803) — monotonic, one per clean→poisoned edge. Sampled by the server to log and
    /// meter each new occurrence.
    #[must_use]
    pub fn ft_spatial_poison_events(&self) -> u64 {
        self.index.borrow().ft_spatial_poison_events()
    }

    /// How many POISON-driven full-store index rebuilds this coordinator has run (`rmp` task #803) —
    /// monotonic. Distinct from
    /// [`ft_spatial_poison_events`](Self::ft_spatial_poison_events), which counts how many times the
    /// marker was POISONED: the gap between the two is exactly what the repair throttle is buying.
    #[must_use]
    pub fn ft_poison_repairs(&self) -> u64 {
        self.ft_poison_repairs.load(Ordering::Relaxed)
    }

    /// How many times a VECTOR index has entered that blocked state over this coordinator's life
    /// (`rmp` task #780) — monotonic, one per index per entry. The server samples it to log each new
    /// occurrence and drive a metric.
    #[must_use]
    pub fn vector_index_conflict_events(&self) -> u64 {
        self.index.borrow().vector_conflict_events()
    }

    /// How many times the derived indexes have been wiped by [`IndexSet::fail_closed`] over this
    /// coordinator's life (`rmp` task #733) — monotonic. The server samples it to log each new
    /// occurrence at `ERROR` and drive a metric; a silent degradation is indistinguishable from a
    /// healthy-but-slow engine, which is how this class of fault stays unnoticed.
    #[must_use]
    pub fn index_fail_closed_events(&self) -> u64 {
        self.index.borrow().fail_closed_events()
    }

    /// How many builds have been **poisoned** over this coordinator's life (`rmp` task #733, M1) —
    /// monotonic. A poisoned build is one a storage fault stopped for good: its index is left
    /// `Populating` (never served, so answers stay correct via the scan) until the store reads cleanly
    /// again. The server samples this to log the event at `ERROR` and drive a metric.
    #[must_use]
    pub fn index_build_poison_events(&self) -> u64 {
        self.poison_events.load(Ordering::Relaxed)
    }

    /// How many poisoned builds are currently parked awaiting resurrection (`rmp` task #733, M1).
    #[must_use]
    pub fn poisoned_index_builds(&self) -> usize {
        let builds = self.builds();
        builds.poisoned_builds.len()
            + builds.poisoned_fulltext_builds.len()
            + builds.poisoned_spatial_builds.len()
    }

    /// Cancels every build — in flight **or parked poisoned** — covering the node-property index
    /// `(label_token, prop_key)`, for a `DROP INDEX`.
    ///
    /// Both queues, always. A poisoned build left behind by a drop is not inert: it is resurrected by
    /// [`retry_poisoned_index_builds`](Self::retry_poisoned_index_builds) the moment the store reads
    /// cleanly again, and its promotion re-creates the dropped index in the **durable** catalog (`rmp`
    /// task #573, auditing `rmp` #733). It also pins the alerting `graphus_index_builds_parked` gauge above
    /// zero for an index that no longer exists.
    fn cancel_node_property_builds(
        pending: &mut VecDeque<PendingIndexBuild>,
        poisoned: &mut Vec<PendingIndexBuild>,
        label_token: u32,
        prop_key: u32,
    ) {
        let covers = |b: &PendingIndexBuild| b.label_token == label_token && b.prop_key == prop_key;
        pending.retain(|b| !covers(b));
        poisoned.retain(|b| !covers(b));
    }

    /// Cancels every **name-keyed** build — in flight *or* parked poisoned — called `name`, for a
    /// `DROP INDEX` or a re-declare of the same name. The full-text / spatial twin of
    /// [`cancel_node_property_builds`](Self::cancel_node_property_builds), and it purges the poison
    /// graveyard for the same load-bearing reason: a parked build that outlives its index is resurrected
    /// later and durably re-creates it.
    fn cancel_named_builds<T>(
        pending: &mut VecDeque<T>,
        poisoned: &mut Vec<T>,
        name: &str,
        name_of: impl Fn(&T) -> &str,
    ) {
        pending.retain(|b| name_of(b) != name);
        poisoned.retain(|b| name_of(b) != name);
    }

    /// Cancels every full-text build called `name` — in flight, parked poisoned, **or** parked on a
    /// write conflict (`rmp` task #778). The full-text-specific wrapper over
    /// [`cancel_named_builds`](Self::cancel_named_builds), which knows only the two generic queues.
    ///
    /// The conflict queue must be purged for exactly the reason the poison graveyard is: a parked build
    /// that outlives its index is resurrected later — here as soon as its blocking writer commits — and
    /// durably re-creates an index the user dropped, or races the fresh build of a re-declared one.
    fn cancel_fulltext_builds(&self, name: &str) {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        Self::cancel_named_builds(
            &mut builds.pending_fulltext_builds,
            &mut builds.poisoned_fulltext_builds,
            name,
            |b| &b.name,
        );
        builds.conflicted_fulltext_builds.retain(|b| b.name != name);
    }

    /// The aggregate index-build numbers (`rmp` task #573) — in-flight and parked build counts, and the
    /// entities still to index across the in-flight ones.
    ///
    /// Deliberately allocation-free and store-free: the engine loop publishes its gauges from this on
    /// **every** iteration, so it must cost nothing when no build is running (the overwhelmingly common
    /// case — three empty-collection `len()`s and a sum over an empty deque). The per-build names live in
    /// [`index_build_progress`](Self::index_build_progress), which allocates and is called only when a
    /// `SHOW INDEXES` actually asks.
    ///
    /// NOTE: `pending` counts **builds**, so it is deliberately narrower than
    /// [`has_pending_index_builds`](Self::has_pending_index_builds), which also reports a queued
    /// `db.resampleIndex` (`rmp` task #572). The engine can therefore be ticking with `pending == 0`: a
    /// resample only sharpens a statistic, it does not populate an index, and reporting it as an
    /// in-flight build would misread as a stalled build to anyone watching the gauge.
    #[must_use]
    pub fn index_build_totals(&self) -> IndexBuildTotals {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // `saturating_sub` on every remainder: a cursor cannot legitimately outrun its snapshot, but a
        // gauge must never underflow into a nonsense value if one ever did.
        let remaining = |cursor: usize, len: usize| len.saturating_sub(cursor);
        IndexBuildTotals {
            pending: builds.pending_builds.len()
                + builds.pending_fulltext_builds.len()
                + builds.pending_spatial_builds.len(),
            // The three poisoned queues counted from the local, not through
            // `poisoned_index_builds()`, which takes the latch this function already holds.
            parked: builds.poisoned_builds.len()
                + builds.poisoned_fulltext_builds.len()
                + builds.poisoned_spatial_builds.len()
                + builds.conflicted_fulltext_builds.len(),
            entities_remaining: builds
                .pending_builds
                .iter()
                .map(|b| remaining(b.cursor, b.snapshot.len()))
                .chain(
                    builds
                        .pending_fulltext_builds
                        .iter()
                        .map(|b| remaining(b.cursor, b.snapshot.len())),
                )
                .chain(
                    builds
                        .pending_spatial_builds
                        .iter()
                        .map(|b| remaining(b.cursor, b.snapshot.len())),
                )
                .sum(),
        }
    }

    /// The progress of every index build this coordinator is carrying — in flight *and* parked poisoned
    /// (`rmp` task #573), named so a `SHOW INDEXES` row can be matched to its build.
    ///
    /// This reads the `cursor`/`snapshot.len()` pair each build already maintains; it adds **no** per-tick
    /// cost to the build loop itself (both reads are O(1); only resolving a node-property build's name
    /// costs a token/catalog lookup, and only when a caller actually asks). Callers are the `SHOW INDEXES`
    /// render and the server's metrics publish, neither of which is on the build's hot path.
    ///
    /// Order is: node-property, full-text, spatial — pending first within each kind, then parked. Callers
    /// match by name rather than position.
    ///
    /// A node-property build whose tokens no longer resolve to names is **omitted** (it has no listing row
    /// to match, so there is nothing to report it against). That is the one case where this disagrees with
    /// [`index_build_totals`](Self::index_build_totals), whose counts are name-independent: the returned
    /// length may be smaller than `pending + parked`. Callers must not treat the two as interchangeable.
    #[must_use]
    pub fn index_build_progress(&self) -> Vec<IndexBuildProgress> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        let store = self.store.borrow();

        // A node-property build is keyed by its `(label_token, prop_key)` tokens, not by a name, so the
        // name is resolved exactly as `list_node_property_indexes` resolves it — same catalog lookup, same
        // `auto_index_name` fallback — or the listing and the progress would disagree on the key.
        let node_name = |b: &PendingIndexBuild| -> Option<String> {
            let label = store.token_name(Namespace::Label, b.label_token)?;
            let property = store.token_name(Namespace::PropKey, b.prop_key)?;
            Some(
                store
                    .node_property_index_name_for(b.label_token, b.prop_key)
                    .unwrap_or_else(|| auto_index_name(&label, &property)),
            )
        };

        let mut out = Vec::with_capacity(
            builds.pending_builds.len()
                + builds.pending_fulltext_builds.len()
                + builds.pending_spatial_builds.len()
                // Counted from the local: `poisoned_index_builds()` takes the latch already held.
                + builds.poisoned_builds.len()
                + builds.poisoned_fulltext_builds.len()
                + builds.poisoned_spatial_builds.len(),
        );
        let mut push = |name: String, done: usize, total: usize, poisoned: bool| {
            out.push(IndexBuildProgress {
                name,
                // A cursor can never legitimately exceed its snapshot, but clamping keeps the public
                // contract (`done <= total`) true by construction rather than by trust — the value feeds a
                // Neo4j-facing percentage that must never exceed 100.
                done: done.min(total),
                total,
                poisoned,
            });
        };

        // Pending first, then parked — the `poisoned` flag comes from WHICH collection the build sits in,
        // so each collection is walked separately with the flag it implies.
        for b in &builds.pending_builds {
            if let Some(name) = node_name(b) {
                push(name, b.cursor, b.snapshot.len(), false);
            }
        }
        for b in &builds.poisoned_builds {
            if let Some(name) = node_name(b) {
                push(name, b.cursor, b.snapshot.len(), true);
            }
        }
        for b in &builds.pending_fulltext_builds {
            push(b.name.clone(), b.cursor, b.snapshot.len(), false);
        }
        for b in &builds.poisoned_fulltext_builds {
            push(b.name.clone(), b.cursor, b.snapshot.len(), true);
        }
        for b in &builds.pending_spatial_builds {
            push(b.name.clone(), b.cursor, b.snapshot.len(), false);
        }
        for b in &builds.poisoned_spatial_builds {
            push(b.name.clone(), b.cursor, b.snapshot.len(), true);
        }
        out
    }

    /// Re-enqueues every **poisoned** build once the store reads cleanly again (`rmp` task #733, M1),
    /// returning whether any build was resurrected.
    ///
    /// Poisoning is what guarantees termination against a permanently-faulting store, but on its own it
    /// is a **one-way door**: the index stays `Populating` — never served, so answers remain correct, but
    /// never accelerated either — with nothing in the process able to bring it back before a restart. A
    /// *transient* fault would therefore cost an index permanently. So a poisoned build is parked, not
    /// discarded, and this probes the store (one `scan_node_ids`) and, when it succeeds, re-enqueues each
    /// parked build with a **fresh snapshot**, a full stall budget and the current wipe epoch — exactly
    /// the state a healthy build starts from.
    ///
    /// Throttled by the same backoff discipline as the degraded rebuild retry, so a broken store cannot
    /// make the engine probe on every command. It must NOT be called from inside
    /// [`advance_index_builds`](Self::advance_index_builds): a build that fails again would be re-enqueued
    /// within the same drain loop, and `while has_pending_index_builds() { advance… }` would never
    /// terminate. The engine calls it *around* the drain, never inside it.
    ///
    /// # Bounding the poison↔resurrect cycle (`rmp` task #733, B2)
    ///
    /// The probe ([`resnapshot_build`](Self::resnapshot_build)) reads only the node *slot* pages, not the
    /// property / label pages a build indexes. A build poisoned by an unreadable **property** page thus
    /// passes the probe, is resurrected, re-drains, hits the same page, and re-poisons. The M1 code reset
    /// the throttle to `0` on every successful probe, so this repeated **every tick** (≈ 500 O(store)
    /// re-scans/second on a live server — a CPU + I/O + log-flood DoS, and the exact spin the round-3
    /// stall budget had eliminated, re-introduced through the resurrection door).
    ///
    /// The fix keeps the throttle **armed** across resurrections and *escalates* it whenever the parked
    /// builds were re-poisoned since the last resurrection (detected via
    /// [`poison_watermark`](Self#structfield.poison_watermark)). The backoff only resets when the
    /// graveyard truly clears — i.e. a resurrected build actually **completed** — so a genuinely-healed
    /// store returns to a fast retry while a permanently-broken one has its retry rate collapse
    /// geometrically to one attempt per [`MAX_DEGRADED_RETRY_BACKOFF`] drains.
    pub fn retry_poisoned_index_builds(&self) -> bool {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // The local, not the accessor: `poisoned_index_builds()` takes the latch this function
        // already holds.
        if builds.poisoned_builds.len()
            + builds.poisoned_fulltext_builds.len()
            + builds.poisoned_spatial_builds.len()
            == 0
        {
            // The graveyard is clear: either nothing was ever poisoned, or a resurrection's builds all
            // COMPLETED. Reset the throttle so a store that has genuinely healed retries promptly.
            self.poison_resurrect_attempts.store(0, Ordering::Relaxed);
            self.poison_retry_skip.store(0, Ordering::Relaxed);
            return false;
        }
        if self.poison_retry_skip.load(Ordering::Relaxed) > 0 {
            self.poison_retry_skip.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        // Probe: can the store even be scanned? If not, stay parked and back off (this is a *different*
        // failure — the slot pages themselves are unreadable — and it escalates like a re-poison).
        let Some(snapshot) = Self::resnapshot_build(&self.store) else {
            self.poison_resurrect_attempts
                .fetch_add(1, Ordering::Relaxed);
            self.poison_retry_skip.store(
                poison_backoff(self.poison_resurrect_attempts.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
            return false;
        };
        let generation = self.index.borrow().wipe_generation();
        for mut build in builds.poisoned_builds.drain(..) {
            build.snapshot.clone_from(&snapshot);
            build.cursor = 0;
            build.stall = BUILD_STALL_BUDGET;
            build.generation = generation;
            builds.pending_builds.push_back(build);
        }
        for mut build in builds.poisoned_fulltext_builds.drain(..) {
            build.snapshot.clone_from(&snapshot);
            build.cursor = 0;
            build.stall = BUILD_STALL_BUDGET;
            build.generation = generation;
            // Fresh snapshot from cursor 0: drop any stale `rmp` #778 conflict record for the same reason
            // the epoch re-snapshot does.
            build.conflict_writers.clear();
            builds.pending_fulltext_builds.push_back(build);
        }
        for mut build in builds.poisoned_spatial_builds.drain(..) {
            build.snapshot.clone_from(&snapshot);
            build.cursor = 0;
            build.stall = BUILD_STALL_BUDGET;
            build.generation = generation;
            builds.pending_spatial_builds.push_back(build);
        }
        // Count this resurrection and ARM the throttle for the NEXT one (`rmp` task #733, B2). The FIRST
        // resurrection after a poisoning is immediate (`attempts` was 0, so this is attempt 1); if these
        // builds re-poison — which happens later in the same drain — the graveyard refills and the next
        // call skips `poison_backoff(attempts)` drains before probing again, doubling each time. If they
        // instead complete, the graveyard clears and the `== 0` branch above resets `attempts` to 0. So a
        // transient fault heals within one or two cycles while a permanent one has its retry rate decay
        // geometrically to one attempt per [`MAX_DEGRADED_RETRY_BACKOFF`] drains.
        self.poison_resurrect_attempts
            .fetch_add(1, Ordering::Relaxed);
        self.poison_retry_skip.store(
            poison_backoff(self.poison_resurrect_attempts.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
        true
    }

    /// Attempts to **repair** a degraded index set by rebuilding it from the store (`rmp` task #733),
    /// returning whether the engine is healthy afterwards.
    ///
    /// A `fail_closed` is usually the result of a *transient* storage fault, and without this the
    /// process would serve scan-only until it was restarted. So the engine calls this from its tick: a
    /// successful rebuild restores every fast path (and re-promotes the indexes in `SHOW INDEXES`),
    /// while a rebuild that faults again simply fails closed once more — always correct, never wrong.
    ///
    /// A full rebuild is **O(store)** and runs synchronously on the engine thread, stalling every query
    /// behind it — so against a *persistently* broken store it must be rare, not merely throttled. Retries
    /// are therefore backed off exponentially up to [`MAX_DEGRADED_RETRY_BACKOFF`] attempts-worth of
    /// skips (≈ 8.7 minutes at the engine's 2 ms tick, and far longer under load, where the counter only
    /// advances once per command). The backoff resets the moment a rebuild succeeds. Deliberately counted
    /// in *attempts* rather than wall-clock: the coordinator must stay deterministic for DST, so it may
    /// not read the clock. A no-op returning `true` when the index set is healthy, so callers can invoke
    /// it unconditionally.
    pub fn retry_degraded_index_rebuild(&self) -> bool {
        // `rmp` task #803 — the trigger covers a POISONED marker as well as a degraded set.
        //
        // A poisoned cross-snapshot full-text/spatial marker pins `effective_ft_spatial_marker` at
        // `u64::MAX`, so every TEXT / FULLTEXT / SPATIAL seek — node and relationship, inline and
        // off-thread — declines to the exact scan, permanently. It was previously UNREACHABLE for
        // repair: `bump_ft_spatial_marker_after_build` (what `CREATE TEXT INDEX` ends with) only raises
        // the watermark and deliberately does not clear a poison, and the only clearing call
        // (`reset_ft_spatial_marker`) lives inside `rebuild_index`, which this driver only ever reached
        // when `is_degraded()`. A poisoned-but-not-degraded set is not degraded, so nothing repaired
        // it: MEASURED, the poison survived `DROP INDEX` + `CREATE TEXT INDEX` and only a process
        // restart cleared it.
        //
        // A full rebuild is the CORRECT repair, not merely the available one: the poison means a
        // rolled-back writer may have removed a posting the index never re-inserted, so the in-memory
        // index can be MISSING a committed posting — a false negative no re-check can resurrect. Only
        // re-deriving from the committed store can prove otherwise.
        //
        // Why that is still true after `rmp` #992. #992 gave every derived-index entry an owner, so a
        // rollback now undoes the entries its transaction created — but only for the five B+-tree-backed
        // kinds (label, node/relationship property, node/relationship composite), which are
        // append-only and whose rolled-back residue is therefore an extra entry. The full-text inverted
        // index and the spatial grid hold only the LATEST state: a write REPLACES or REMOVES a posting,
        // so a rolled-back mutator leaves a hole rather than a surplus, and a hole is the one thing an
        // undo log of "entries this transaction created" does not describe. Repairing that needs the
        // committed store, which is what this does. Do not read #992 as having retired this gate.
        //
        // SPIN SAFETY: unlike `has_pending_index_builds` — which callers SPIN on, and which is why
        // `rmp` #780 refused to widen it — this function is never called inside a loop. Its three
        // production call sites (`advance_index_builds`, `LocalEngine::drain_index_builds`,
        // `maintain_degraded_indexes`) each call it at most once per command/tick, and the attempt is
        // additionally throttled by the shared exponential backoff below. A workload that re-poisons on
        // every attempt therefore costs one bounded O(store) rebuild per backoff window, never a hot
        // loop.
        //
        // THROTTLE, and why the pre-existing one was NOT enough. `degraded_retry_backoff` arms only when
        // a repair FAILS, which is the right shape for a faulting device but the wrong one here: a
        // poison repair SUCCEEDS every time (the rebuild clears it) and then the very next rolled-back
        // remover poisons again. With only that backoff, an abort-heavy workload on an indexed property
        // — SSI aborts under contention are ordinary in this engine — would pay a full O(store) rebuild
        // of EVERY index on EVERY command. That is a worse regression than the defect, which at least
        // left queries running. So a poison-ONLY repair carries its own backoff, armed on SUCCESS and
        // decayed whenever the engine is found healthy. Throttling is always safe here: while the
        // repair waits, the marker stays poisoned and reads stay on the exact scan — correct, and
        // exactly the pre-fix behaviour, so a throttled repair is never worse than not having one.
        let (degraded, poisoned) = {
            let idx = self.index.borrow();
            (idx.is_degraded(), idx.ft_spatial_poisoned())
        };
        if !degraded && !poisoned {
            // Nothing to repair. Decay the poison backoff so a burst of aborts throttles the repair but
            // a subsequent quiet period restores an immediate response to the next isolated poisoning.
            self.ft_poison_repair_backoff.store(
                (self.ft_poison_repair_backoff.load(Ordering::Relaxed) / 2).max(1),
                Ordering::Relaxed,
            );
            return true;
        }
        // A poison-only repair waits its own turn. A DEGRADED set deliberately does not: that is a
        // storage fault that cost the engine its indexes, and its cadence stays exactly as `rmp` #733
        // set it.
        if !degraded && self.ft_poison_repair_skip.load(Ordering::Relaxed) > 0 {
            self.ft_poison_repair_skip.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        if self.degraded_retry_skip.load(Ordering::Relaxed) > 0 {
            self.degraded_retry_skip.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        if !degraded {
            self.ft_poison_repairs.fetch_add(1, Ordering::Relaxed);
        }
        Self::rebuild_index(&self.store, &self.index);
        // Repaired only if BOTH conditions cleared. `rebuild_index` ends in `reset_ft_spatial_marker`,
        // which clears the poison — but it bails to `fail_closed` (which re-poisons) on a read fault, so
        // the two conditions genuinely have to be tested together.
        if self.index.borrow().is_degraded() || self.index.borrow().ft_spatial_poisoned() {
            // Still faulting: back off so a permanently-broken store cannot make the engine thread burn
            // a whole store scan every tick (correctness is unaffected either way — reads are on scans).
            let doubled = self
                .degraded_retry_backoff
                .load(Ordering::Relaxed)
                .saturating_mul(2)
                .min(MAX_DEGRADED_RETRY_BACKOFF);
            self.degraded_retry_backoff
                .store(doubled, Ordering::Relaxed);
            self.degraded_retry_skip.store(
                self.degraded_retry_backoff.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            false
        } else {
            // Repaired. The backoff is **halved**, not reset (`rmp` task #733, M3): an *intermittent*
            // device — fail, repair, fail, repair — would otherwise re-arm a 1-attempt backoff on every
            // success, so the very next fault triggers another O(store) synchronous rebuild on the engine
            // thread and the engine spends its life re-scanning the store. Decaying the backoff lets a
            // genuinely-healed store return to a fast retry within a few cycles, while a flapping one
            // stays throttled.
            self.degraded_retry_backoff.store(
                (self.degraded_retry_backoff.load(Ordering::Relaxed) / 2).max(1),
                Ordering::Relaxed,
            );
            self.degraded_retry_skip.store(0, Ordering::Relaxed);
            if !degraded {
                // A poison-only repair succeeded: arm and GROW its own backoff, so a workload that
                // keeps re-poisoning cannot buy a whole-store rebuild per command. An isolated
                // poisoning pays one skip and the decay above erases it within a few healthy commands.
                self.ft_poison_repair_skip.store(
                    self.ft_poison_repair_backoff.load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                let doubled = self
                    .ft_poison_repair_backoff
                    .load(Ordering::Relaxed)
                    .saturating_mul(2)
                    .min(MAX_DEGRADED_RETRY_BACKOFF);
                self.ft_poison_repair_backoff
                    .store(doubled, Ordering::Relaxed);
            }
            true
        }
    }

    /// Re-fills every VECTOR index whose build was blocked by an uncommitted writer, once ALL of that
    /// index's recorded writers have resolved (`rmp` task #780). Returns whether any re-fill ran.
    ///
    /// # Why resolution alone is not the repair
    ///
    /// A blocked build SKIPPED the conflicted entity rather than baking its uncommitted embedding, so
    /// the graph is missing that entity. A k-NN can drop a candidate but never resurrect one, and
    /// nothing re-inserts it when the writer resolves — MEASURED: before this, the wrong answer survived
    /// the writer's ROLLBACK for the life of the process, healed only by a reopen (the graph is
    /// ephemeral). The repair therefore has to be an actual re-fill: wipe the graph, re-scan, re-insert.
    ///
    /// # Why it is gated on the writers, and why that is cheap
    ///
    /// The re-fill is an O(store) scan on the command path, so attempting it while a blocking writer is
    /// still open would re-scan on every command for as long as that transaction stayed open. Waiting
    /// costs one [`RecordStore::is_txn_active`](graphus_storage::RecordStore::is_txn_active) lookup per
    /// recorded writer and fires only when the re-fill can actually succeed. A writer that COMMITS and
    /// one that ABORTS both resolve it: after either, the newest version of the covered property is a
    /// settled one. (The predicate is the Active Transaction Table, NOT `CommitRegistry::outcome`, which
    /// is always-false for a running transaction — `rmp` #522 / #778.)
    ///
    /// It is throttled for the reason [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild)
    /// documents: overlapping writers resolve one after another, so an unthrottled repair would run one
    /// O(store) re-fill per writer generation, forever. A re-conflict doubles the backoff up to
    /// [`MAX_DEGRADED_RETRY_BACKOFF`]. A repair that leaves the storm still running — some vector index
    /// still blocked — HALVES it (a flapping conflict would otherwise buy a full re-scan on every
    /// success); a repair that reaches FULL quiescence (no vector index, node or rel, still blocked)
    /// DRAINS it to the floor (`rmp` task #802), so the coordinator-global backoff cannot outlive the
    /// storm that armed it and spend itself as a wide skip on the next unrelated index to block.
    fn retry_conflicted_vector_builds(&self) -> bool {
        let node_keys = self.index.borrow().conflicted_vector();
        let rel_keys = self.index.borrow().conflicted_vector_rel();
        if node_keys.is_empty() && rel_keys.is_empty() {
            return false;
        }
        let resolved = |writers: &[TxnId], store: &SharedRef<RecordStore<D, S>>| {
            let store = store.borrow();
            writers.iter().all(|&w| !store.is_txn_active(w))
        };

        // Partition first: only indexes whose writers have ALL settled are repairable now.
        let ready_nodes: Vec<(u32, u32)> = node_keys
            .into_iter()
            .filter(|&(t, p)| {
                let writers = self.index.borrow().vector_blockers(t, p).to_vec();
                resolved(&writers, &self.store)
            })
            .collect();
        let ready_rels: Vec<(u32, u32)> = rel_keys
            .into_iter()
            .filter(|&(t, p)| {
                let writers = self.index.borrow().vector_rel_blockers(t, p).to_vec();
                resolved(&writers, &self.store)
            })
            .collect();
        if ready_nodes.is_empty() && ready_rels.is_empty() {
            // Still blocked — not an attempt, so it neither spends nor arms the throttle.
            return false;
        }
        if self.vector_conflict_retry_skip.load(Ordering::Relaxed) > 0 {
            self.vector_conflict_retry_skip
                .fetch_sub(1, Ordering::Relaxed);
            return false;
        }

        for (token, prop_key) in &ready_nodes {
            self.index
                .borrow_mut()
                .reset_vector_for_refill(*token, *prop_key);
        }
        for (token, prop_key) in &ready_rels {
            self.index
                .borrow_mut()
                .reset_vector_rel_for_refill(*token, *prop_key);
        }
        // Arm the per-entity fault signal (`rmp` task #733) BEFORE the re-fill, exactly as every sibling
        // build driver does. `index_one_*_vector` raises this when it cannot read an entity's labels or
        // property chain, and an entity missing from the graph is a candidate a k-NN can never
        // resurrect. Without this bracket the driver published a silently INCOMPLETE index as fully
        // repaired — the same wrong-answer-with-no-signal the whole task exists to remove, re-entering
        // through the repair door.
        self.index.borrow_mut().clear_rebuild_gap();

        // Re-fill from a fresh scan. `index_one_*_vector` re-runs the same conflict gate, so a writer
        // that opened in the meantime simply re-records itself and the index stays on the exact scan.
        if !ready_nodes.is_empty() {
            // Bind the scan result BEFORE matching: a `self.store.borrow_mut()` temporary inside the
            // match scrutinee stays alive for the whole match, and `index_one_node_vector` borrows the
            // same cell — which panicked "RefCell already borrowed" the first time this ran.
            let scanned = self.store.borrow_mut().scan_node_ids();
            match scanned {
                Ok(ids) => {
                    for id in ids {
                        Self::index_one_node_vector(&self.store, &self.index, id, &ready_nodes);
                    }
                }
                Err(_) => {
                    // The scan faulted: the graph is now WIPED and only partially re-filled, which is
                    // exactly the state that must never be served. Re-record every writer we cleared so
                    // the index keeps declining to the exact scan until a later attempt succeeds.
                    for (token, prop_key) in &ready_nodes {
                        self.index.borrow_mut().note_vector_build_conflict(
                            *token,
                            *prop_key,
                            REFILL_FAULT_BLOCKER,
                        );
                    }
                }
            }
        }
        if !ready_rels.is_empty() {
            // Same borrow discipline as the node arm above.
            let scanned = self.store.borrow().scan_rel_ids();
            match scanned {
                Ok(ids) => {
                    for id in ids {
                        Self::index_one_rel_vector(&self.store, &self.index, id, &ready_rels);
                    }
                }
                Err(_) => {
                    for (token, prop_key) in &ready_rels {
                        self.index.borrow_mut().note_vector_rel_build_conflict(
                            *token,
                            *prop_key,
                            REFILL_FAULT_BLOCKER,
                        );
                    }
                }
            }
        }

        // A per-entity read fault during the re-fill is treated EXACTLY as a whole-scan fault: the graph
        // is now wiped and only partially re-filled, so re-record a synthetic blocker on every index we
        // touched and keep serving the exact scan until a later attempt succeeds.
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            for (token, prop_key) in &ready_nodes {
                self.index.borrow_mut().note_vector_build_conflict(
                    *token,
                    *prop_key,
                    REFILL_FAULT_BLOCKER,
                );
            }
            for (token, prop_key) in &ready_rels {
                self.index.borrow_mut().note_vector_rel_build_conflict(
                    *token,
                    *prop_key,
                    REFILL_FAULT_BLOCKER,
                );
            }
        }

        // `rmp` #803: the re-fill above drove `insert_vector_value` / `insert_vector_rel_value`, which
        // raise the shared transient dirty flag. Discard it on EVERY exit from here (this driver had no
        // disposal at all, so it leaked on its success path too, not merely on a bail): the re-fill
        // reflects committed state, so it must never be attributed to the next write statement's
        // transaction. `clear_ft_spatial_dirty` rather than `bump_ft_spatial_marker_after_build`
        // deliberately — this re-fill re-keys only the VECTOR graph, and vector does not consult the
        // full-text/spatial watermark, so raising that watermark would needlessly send unrelated TEXT /
        // FULLTEXT / SPATIAL readers to the exact scan.
        self.index.borrow_mut().clear_ft_spatial_dirty();

        // Did every attempted index come back clean?
        let repaired = ready_nodes
            .iter()
            .all(|&(t, p)| self.index.borrow().vector_blockers(t, p).is_empty())
            && ready_rels
                .iter()
                .all(|&(t, p)| self.index.borrow().vector_rel_blockers(t, p).is_empty());
        if repaired {
            // `rmp` task #802 — DRAIN on full quiescence, HALVE otherwise.
            //
            // The backoff is a coordinator-GLOBAL throttle shared by every vector index (node and rel):
            // one index's overlapping-writer storm inflates it, and it is spent as `skip` on the FIRST
            // re-conflict of the NEXT index to block — so a wide backoff left standing after its cause is
            // gone makes a fresh, singly-conflicted index decline to the exact brute-force scan for
            // `backoff` further commands, silently, while `SHOW INDEXES` reports ONLINE. Halving alone
            // decays it over ~log2(backoff) later repairs, so the residue outlives the storm that armed
            // it (measured: 513 commands on an unrelated index after a burst that peaked at 512).
            //
            // When the WHOLE vector blocker set is now empty — no index, this one or any other, is still
            // declining — the storm is genuinely over, so reset the throttle to its floor. Draining is
            // sound precisely BECAUSE the set is empty: a re-conflicting workload keeps a non-empty set
            // (a still-open writer re-records itself during this very re-fill, taking the `else` branch
            // below instead) or leaves a sibling index blocked, and either way never reaches this reset —
            // so the anti-hot-loop guard (`rmp` #733 / #780) that the backoff exists for is preserved: a
            // storm still climbs 1→2→4→…→cap and is never re-armed to a 1-drain window mid-storm.
            if self.index.borrow().blocked_vector_indexes() == 0 {
                self.vector_conflict_retry_backoff
                    .store(1, Ordering::Relaxed);
            } else {
                let halved =
                    (self.vector_conflict_retry_backoff.load(Ordering::Relaxed) / 2).max(1);
                self.vector_conflict_retry_backoff
                    .store(halved, Ordering::Relaxed);
            }
            self.vector_conflict_retry_skip.store(0, Ordering::Relaxed);
        } else {
            let doubled = self
                .vector_conflict_retry_backoff
                .load(Ordering::Relaxed)
                .saturating_mul(2)
                .min(MAX_DEGRADED_RETRY_BACKOFF);
            self.vector_conflict_retry_backoff
                .store(doubled, Ordering::Relaxed);
            self.vector_conflict_retry_skip.store(
                self.vector_conflict_retry_backoff.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
        true
    }

    /// Re-drives every full-text build that `rmp` task #778 parked, once the in-flight writers that
    /// blocked it have resolved. Returns whether anything was re-driven.
    ///
    /// This is the **resurrection path** for the option (b) conflict gate, and the reason a conflict is a
    /// pause rather than a poison. Two shapes are parked and both are drained here:
    ///
    /// - a **node** build, parked in [`conflicted_fulltext_builds`](Self#structfield.conflicted_fulltext_builds)
    ///   by [`advance_fulltext_build`](Self::advance_fulltext_build): re-enqueued from a fresh snapshot,
    ///   so it re-visits the node it skipped and this time bakes the settled value;
    /// - a **relationship** (or already-`Online` node) index, demoted in memory by
    ///   [`rebuild_index`](Self::rebuild_index), whose repair is a fresh `rebuild_index` — its
    ///   re-registration pass restores each index's state from the durable catalog and then refills, so an
    ///   index returns to `Online` only by being rebuilt with no conflict remaining.
    ///
    /// # Why it is gated on the writers, and why that is cheap
    ///
    /// Both repairs are O(store) scans, and this runs on the command path — so re-attempting while the
    /// blocking writer is still open would re-scan the store on every command for as long as one
    /// transaction stayed open. Waiting for the recorded writers costs one
    /// [`RecordStore::is_txn_active`](graphus_storage::RecordStore::is_txn_active) lookup each and fires
    /// only when the repair can actually succeed. A writer that commits and one that aborts both resolve
    /// it: after either, the newest version of the covered property is a settled one. (Note the predicate
    /// — the Active Transaction Table, NOT `CommitRegistry::outcome`, which is always-false for a running
    /// transaction and is the root of `rmp` #522 and #778 alike.)
    ///
    /// It is additionally **throttled**, for the reason
    /// [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild) documents: this conflict is
    /// inherently flapping — overlapping write transactions resolve one after another — so an unthrottled
    /// repair would run one O(store) rebuild per writer generation, on the engine thread, forever.
    fn retry_conflicted_fulltext_builds(&self) -> bool {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        let rebuild_blocked = !self.index.borrow().ft_demoted_blockers().is_empty();
        if builds.conflicted_fulltext_builds.is_empty() && !rebuild_blocked {
            return false;
        }
        // The same liveness signal the gate used — the Active Transaction Table, never
        // `CommitRegistry::outcome` (see `active_writer_holds_newest_covered`). Here the naive predicate
        // would have been dead in the OPPOSITE direction: reporting every writer resolved would make the
        // repair fire immediately and re-park in a loop, re-scanning the store on every command.
        let resolved = |writers: &[TxnId], store: &SharedRef<RecordStore<D, S>>| {
            let store = store.borrow();
            writers.iter().all(|&w| !store.is_txn_active(w))
        };

        // (1) The synchronous / relationship shape: a `rebuild_index` demoted the full-text indexes.
        let mut acted = false;
        if rebuild_blocked {
            let writers: Vec<TxnId> = self.index.borrow().ft_demoted_blockers().to_vec();
            if !resolved(&writers, &self.store) {
                // Still blocked — not an attempt, so it neither spends nor arms the throttle.
            } else if self.conflict_retry_skip.load(Ordering::Relaxed) > 0 {
                self.conflict_retry_skip.fetch_sub(1, Ordering::Relaxed);
            } else {
                // `rebuild_index` clears the record via `IndexSet::clear` and re-raises it if the conflict
                // persists (a writer that opened since), so this cannot livelock: it re-runs only when the
                // recorded writers have settled.
                Self::rebuild_index(&self.store, &self.index);
                if self.index.borrow().ft_demoted_blockers().is_empty() {
                    // Repaired. HALVE rather than reset, exactly as `retry_degraded_index_rebuild`
                    // documents: a flapping conflict — repair, re-conflict, repair — would otherwise
                    // re-arm a 1-drain backoff on every success, so the next overlapping writer buys
                    // another full store scan and the engine spends its life re-scanning.
                    self.conflict_retry_backoff.store(
                        (self.conflict_retry_backoff.load(Ordering::Relaxed) / 2).max(1),
                        Ordering::Relaxed,
                    );
                    self.conflict_retry_skip.store(0, Ordering::Relaxed);
                } else {
                    // Re-conflicted with a writer that opened in the meantime: widen the window.
                    let doubled = self
                        .conflict_retry_backoff
                        .load(Ordering::Relaxed)
                        .saturating_mul(2)
                        .min(MAX_DEGRADED_RETRY_BACKOFF);
                    self.conflict_retry_backoff
                        .store(doubled, Ordering::Relaxed);
                    self.conflict_retry_skip.store(
                        self.conflict_retry_backoff.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                }
                acted = true;
            }
        }

        // (2) The chunked node-build shape.
        if !builds.conflicted_fulltext_builds.is_empty() {
            let ready: Vec<usize> = builds
                .conflicted_fulltext_builds
                .iter()
                .enumerate()
                .filter(|(_, b)| resolved(&b.conflict_writers, &self.store))
                .map(|(i, _)| i)
                .collect();
            // The probe below is a store scan, so it is spent from the SAME throttle as the rebuild
            // repair: a faulting store returns `None`, removes nothing, and would otherwise be re-probed
            // on every command forever (the guard `retry_poisoned_index_builds` applies to its identical
            // probe via `poison_retry_skip`).
            if !ready.is_empty() && self.conflict_retry_skip.load(Ordering::Relaxed) > 0 {
                self.conflict_retry_skip.fetch_sub(1, Ordering::Relaxed);
            } else if !ready.is_empty()
                && let Some(snapshot) = Self::resnapshot_build(&self.store)
            {
                let generation = self.index.borrow().wipe_generation();
                // Descending, so each removal leaves the lower indices valid.
                for i in ready.into_iter().rev() {
                    let mut build = builds.conflicted_fulltext_builds.swap_remove(i);
                    build.snapshot.clone_from(&snapshot);
                    build.cursor = 0;
                    build.stall = BUILD_STALL_BUDGET;
                    build.generation = generation;
                    build.conflict_writers.clear();
                    builds.pending_fulltext_builds.push_back(build);
                    acted = true;
                }
            }
        }
        acted
    }

    /// Advances the front non-blocking index build by up to `budget` nodes (`rmp` task #91), returning
    /// whether **any** build remains pending afterwards.
    ///
    /// For the front build it indexes the next `budget` snapshot nodes (each via the shared
    /// `index_one_node` helper, so the per-node logic matches the full
    /// rebuild). When the front build's cursor reaches the end of its snapshot it is **complete**: the
    /// catalog entry is durably flipped to [`IndexState::Online`] in a committed transaction, the
    /// in-memory state is promoted, and the build is dequeued — after which the planner begins routing
    /// seeks to it. Per-call work is bounded by `budget` so a build never monopolises the engine
    /// thread (the responsiveness guarantee).
    ///
    /// A `budget` of `0` performs no indexing but still returns the pending state (callers should pass
    /// a positive chunk size). A `budget` of [`usize::MAX`] means "advance this build to completion" and
    /// is legal from **any** cursor position — the chunk bounds saturate rather than overflow (`rmp` task
    /// #573). If the durable promotion commit fails, the build is left in place `Populating` (still
    /// correct via the scan fallback) to be retried on the next call/open.
    pub fn advance_index_builds(&self, budget: usize) -> bool
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        // Repair a fail-closed index set FIRST (`rmp` task #733). This runs on the **command** path (the
        // engine drives an index build after every command), not just on the idle tick — under sustained
        // load an idle tick may never come, and a build cannot promote while the set is degraded, so
        // without this the engine would stay scan-only for as long as it was busy. The attempt itself is
        // exponentially backed off inside `retry_degraded_index_rebuild`, so a permanently-faulting store
        // costs at most one bounded probe per backoff window.
        // `rmp` #803: a poisoned marker is repairable work too, and its repair lives behind the same
        // driver — so this gate must admit it or the whole widening above is unreachable from here.
        let needs_repair = {
            let idx = self.index.borrow();
            idx.is_degraded() || idx.ft_spatial_poisoned()
        };
        if needs_repair {
            let _healed = self.retry_degraded_index_rebuild();
        }
        // Re-drive any full-text build paused by an in-flight writer whose conflict has since resolved
        // (`rmp` task #778). Sited HERE, on the command path, for the reason the degraded repair above
        // documents — and additionally because the poison graveyard's own resurrection runs on the
        // threaded engine only from the idle tick, whose gate does not count parked builds (`rmp` #763).
        // A paused index is `Populating`, so it is correct-but-unaccelerated until this fires.
        let _resumed = self.retry_conflicted_fulltext_builds();
        // Re-fill any VECTOR index whose build skipped an entity under an uncommitted writer, once every
        // recorded writer has resolved (`rmp` task #780). Sited here for the same reason: while blocked,
        // the index serves a correct but O(entities x dim) exact scan, so the repair must not wait for an
        // idle tick that a loaded engine may never reach.
        let _refilled = self.retry_conflicted_vector_builds();
        // Drive a node-property build first if one is pending; then a full-text build; then a spatial
        // build. Processing one queue per call keeps the per-call work bounded by `budget` for any kind.
        // Read the two predicates under a SHORT hold and drop it before dispatching: each
        // `advance_*` takes the latch itself, and holding it across the call is the re-entrancy the
        // tripwire in `builds()` refuses.
        let (node_pending, fulltext_pending) = {
            let builds = self.builds();
            (
                !builds.pending_builds.is_empty(),
                !builds.pending_fulltext_builds.is_empty(),
            )
        };
        if node_pending {
            self.advance_node_property_build(budget);
        } else if fulltext_pending {
            self.advance_fulltext_build(budget);
        } else {
            self.advance_spatial_build(budget);
        }
        // Then one queued resample (`rmp` task #572) — after the builds, because a build makes an index
        // usable while a resample only sharpens an estimate. ONE per call keeps this tick bounded: each
        // is a full label scan, and `db.resampleOutdatedIndexes` can queue one per declared index.
        //
        // TERMINATION: the request is POPPED before the work and is never re-queued, even on failure, so
        // the queue strictly shrinks and `while has_pending_index_builds() { advance… }` always ends.
        // (`rmp` #733 learned this the hard way: work that stays queued after a failed attempt spins the
        // drain loop at 100% CPU forever.)
        self.drain_one_pending_resample();
        self.has_pending_index_builds()
    }

    /// Executes one queued `db.resampleIndex` request (`rmp` task #572), if any.
    ///
    /// The request is popped first and never re-queued (see the termination note in
    /// [`advance_index_builds`](Self::advance_index_builds)); the recompute itself is the best-effort
    /// [`seed_index_histogram`](Self::seed_index_histogram), which runs it in its own yield-free
    /// auto-commit transaction.
    fn drain_one_pending_resample(&self)
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        let Some((label, property)) = self.index.borrow_mut().pop_pending_resample() else {
            return;
        };
        // Resolve to tokens; a request naming a label/property whose token vanished is dropped (it can
        // carry no histogram anyway).
        let tokens = {
            let store = self.store.borrow();
            store
                .token_id(Namespace::Label, &label)
                .zip(store.token_id(Namespace::PropKey, &property))
        };
        if let Some((label_token, prop_key)) = tokens {
            self.seed_index_histogram(label_token, prop_key);
        }
    }

    /// Advances the front **node-property** build by up to `budget` nodes (`rmp` task #91), promoting
    /// + dequeuing it when complete.
    fn advance_node_property_build(&self, budget: usize)
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // (1) EPOCH CHECK (`rmp` task #733). Was the index set wiped by a `fail_closed` since this build
        // last ran? The build queues live on the coordinator, out of `IndexSet`'s reach, so a wipe empties
        // the half-built tree without telling the build. Resuming from the old cursor would index only the
        // TAIL of the snapshot and then promote the index `Online` over the hole. And restarting at
        // cursor 0 over the ORIGINAL snapshot is *still* not enough — the wipe also destroyed the
        // maintenance writes for rows created after the snapshot — so the snapshot itself is re-taken.
        // See `resnapshot_build`.
        let generation = self.index.borrow().wipe_generation();
        if builds
            .pending_builds
            .front()
            .is_some_and(|b| b.generation != generation)
        {
            let Some(fresh) = Self::resnapshot_build(&self.store) else {
                // The store cannot be scanned: POISON the build (drop it un-promoted). The index stays
                // `Populating`, so it is never served — correct, just unaccelerated — and the degraded
                // rebuild retry will repopulate its tree. Never resume a build we cannot re-base.
                Self::poison_front(
                    &mut builds.pending_builds,
                    &mut builds.poisoned_builds,
                    &self.poison_events,
                );
                return;
            };
            if let Some(build) = builds.pending_builds.front_mut() {
                build.snapshot = fresh;
                build.cursor = 0;
                build.generation = generation;
                build.stall = BUILD_STALL_BUDGET;
            }
        }

        let Some(build) = builds.pending_builds.front_mut() else {
            return;
        };

        // Index up to `budget` nodes from the snapshot, starting at the cursor.
        //
        // `saturating_add`, not `+`: `budget` is caller-supplied and `usize::MAX` is the documented way to
        // ask for "the whole build" — `LocalEngine::drain_index_builds` (the DST driver) passes exactly
        // that, in a loop. Once the cursor is non-zero, `cursor + usize::MAX` overflows: a debug panic, and
        // in release a wrap to `end < start` that panics on the slice range below.
        //
        // A non-zero cursor here is REACHABLE, not hypothetical (`rmp` task #573). These bounds are
        // computed BEFORE the gap check and the degraded gate, so once any call leaves a build pending
        // with `cursor == total` — which the degraded gate below does, and which a failed promotion commit
        // does — the NEXT call overflows regardless of whether the store has since healed. Only a wipe
        // resets a cursor (via the epoch check above); healing does not. Pinned by
        // `index_fail_closed.rs::the_dst_drain_loop_does_not_overflow_on_a_build_parked_at_the_degraded_gate`.
        let registered = [(build.label_token, build.prop_key)];
        let start = build.cursor;
        let end = build
            .snapshot
            .len()
            .min(build.cursor.saturating_add(budget));
        let chunk: Vec<u64> = build.snapshot[start..end].to_vec();
        let total = build.snapshot.len();
        // A clean slate: only THIS chunk's read faults may fail THIS build (`rmp` task #733).
        self.index.borrow_mut().clear_rebuild_gap();
        for id in chunk {
            Self::index_one_node(&self.store, &self.index, id, &registered);
        }

        // (2) GAP CHECK. Could a node in this chunk not be read? Then the tree has a hole a seek could
        // never resurrect, so the cursor does NOT advance and the index is NOT promoted — the chunk is
        // retried. A *transient* fault heals within a few attempts; a **persistent** one (the model this
        // project assumes: checksum / torn page) would otherwise retry forever, and
        // `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()`, so that is an
        // infinite loop at 100% CPU re-scanning the store. Hence the bounded stall budget: when it is
        // exhausted the build is POISONED (dropped, un-promoted, index left `Populating` and therefore
        // never served). Terminates, never holes, never spins.
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            if Self::stall_or_poison(&mut builds.pending_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut builds.pending_builds,
                    &mut builds.poisoned_builds,
                    &self.poison_events,
                );
            }
            return;
        }

        let Some(build) = builds.pending_builds.front_mut() else {
            return;
        };
        build.cursor = end;
        // Refill the stall budget ONLY on real progress. An **empty** chunk (`start == end == total`, the
        // state of a completed build that keeps being re-driven because the degraded gate below will not
        // let it promote) is not progress: refilling on it resets the budget faster than the gate spends
        // it, so the build never poisons, `has_pending_index_builds()` never goes false, and
        // `LocalEngine::drain_index_builds` spins forever (`rmp` task #733).
        if end > start {
            build.stall = BUILD_STALL_BUDGET;
        }
        if build.cursor < total {
            return; // more of this build remains.
        }

        // (3) BELT AND BRACES. Never publish into a WIPED index set: while the engine is degraded, the
        // derived structures are known-untrustworthy and a repair rebuild is pending, so an `Online`
        // promotion now could only be a claim we cannot back. Stall (bounded) and let the repair run
        // first; on exhaustion the build is poisoned rather than promoted.
        if self.index.borrow().is_degraded() {
            if Self::stall_or_poison(&mut builds.pending_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut builds.pending_builds,
                    &mut builds.poisoned_builds,
                    &self.poison_events,
                );
            }
            return;
        }

        let Some(build) = builds.pending_builds.front_mut() else {
            return;
        };
        // The front build's snapshot is fully indexed: promote it durably to `Online`, then dequeue.
        let (label_token, prop_key) = (build.label_token, build.prop_key);
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().set_node_property_index(
            txn,
            label_token,
            prop_key,
            IndexState::Online,
        );
        if self.store.borrow_mut().commit(txn).is_err() {
            // The durable flip failed; leave the build pending `Populating` and retry next call.
            return;
        }
        self.index
            .borrow_mut()
            .set_node_property_state(label_token, prop_key, IndexState::Online);
        builds.pending_builds.pop_front();
        // The build is complete and the index is durably Online: seed its selectivity histogram
        // (`rmp` task #572). This is the production `CREATE INDEX` completion point — the server drives
        // `begin_online_node_composite_index_named`, whose arity-1 case is this non-blocking build — so
        // this is what makes a declared index born with real statistics. Done *after* `pop_front` so no
        // build borrow is outstanding across the statement seam, and only on the promotion tick (once
        // per created index), never per chunk.
        // The build is off the queue; release the latch BEFORE seeding the histogram, which writes
        // through the store and must not run with an index-build hold outstanding.
        drop(guard);
        self.seed_index_histogram(label_token, prop_key);
    }

    /// Advances the front **full-text** build by up to `budget` nodes (`rmp` task #72), promoting +
    /// dequeuing it when complete. The full-text analogue of
    /// [`advance_node_property_build`](Self::advance_node_property_build): each chunk re-indexes a
    /// bounded number of snapshot nodes' text into the inverted index via the shared
    /// [`index_one_node_fulltext`](Self::index_one_node_fulltext) helper, then on completion the named
    /// catalog entry is durably flipped to [`IndexState::Online`].
    fn advance_fulltext_build(&self, budget: usize) {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // (1) EPOCH CHECK + RE-SNAPSHOT, exactly as `advance_node_property_build` documents (`rmp` #733).
        // The full-text index escapes the worst of a stale resume by accident (the `rmp` #467 marker
        // poison keeps readers off a wiped inverted index), but it must not be left half-filled-and-
        // `Online` either — and the marker is cleared by the very rebuild that repairs the set.
        let generation = self.index.borrow().wipe_generation();
        if builds
            .pending_fulltext_builds
            .front()
            .is_some_and(|b| b.generation != generation)
        {
            let Some(fresh) = Self::resnapshot_build(&self.store) else {
                Self::poison_front(
                    &mut builds.pending_fulltext_builds,
                    &mut builds.poisoned_fulltext_builds,
                    &self.poison_events,
                ); // poison: never resume a build we cannot re-base.
                return;
            };
            if let Some(build) = builds.pending_fulltext_builds.front_mut() {
                build.snapshot = fresh;
                build.cursor = 0;
                build.generation = generation;
                build.stall = BUILD_STALL_BUDGET;
                // A restart from cursor 0 re-visits every entity, so any conflict this build recorded on
                // its previous pass is about to be re-detected if it still holds (`rmp` task #778).
                // Carrying it forward would park the fresh, clean pass on a transaction that is no longer
                // relevant — the same mis-attribution the per-chunk clear exists to prevent.
                build.conflict_writers.clear();
            }
        }
        let Some(build) = builds.pending_fulltext_builds.front_mut() else {
            return;
        };
        let total = build.snapshot.len();
        let start = build.cursor;
        // `saturating_add` — see the node-property build's chunk bounds (`rmp` task #573): a `usize::MAX`
        // budget past a non-zero cursor would otherwise overflow and panic the engine thread.
        let end = total.min(build.cursor.saturating_add(budget));
        let chunk: Vec<u64> = build.snapshot[start..end].to_vec();
        let name = build.name.clone();
        build.cursor = end;
        let done = end >= total;

        // A clean slate: only THIS chunk's read faults may fail THIS build (`rmp` task #733), and only
        // THIS chunk's write conflicts are attributed to it (`rmp` task #778).
        self.index.borrow_mut().clear_rebuild_gap();
        self.index.borrow_mut().clear_ft_build_conflict();
        for id in chunk {
            Self::index_one_node_fulltext(&self.store, &self.index, id);
        }
        // Drain this chunk's conflict record onto the BUILD before anything else can clear it — see
        // `PendingFulltextBuild::conflict_writers` for why it cannot be read off the index set later.
        let chunk_blockers: Vec<TxnId> = self.index.borrow().ft_build_conflict_writers().to_vec();
        if !chunk_blockers.is_empty() {
            self.index.borrow_mut().clear_ft_build_conflict();
            if let Some(build) = builds.pending_fulltext_builds.front_mut() {
                for w in chunk_blockers {
                    if !build.conflict_writers.contains(&w) {
                        build.conflict_writers.push(w);
                    }
                }
            }
        }
        // (2) GAP CHECK. A node this chunk could not read is missing from the inverted index for good, and
        // no per-candidate re-check can resurrect it. Rewind and retry — bounded by the stall budget, so a
        // persistent fault poisons the build instead of spinning the engine forever (`rmp` task #733).
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            if Self::stall_or_poison(&mut builds.pending_fulltext_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut builds.pending_fulltext_builds,
                    &mut builds.poisoned_fulltext_builds,
                    &self.poison_events,
                );
            } else if let Some(build) = builds.pending_fulltext_builds.front_mut() {
                build.cursor = start;
            }
            // `rmp` #803: this rewind is AFTER the chunk loop, which raised the transient dirty flag.
            // Discard it rather than let the next unrelated write statement be charged with it.
            self.index.borrow_mut().clear_ft_spatial_dirty();
            return;
        }
        if end > start
            && let Some(build) = builds.pending_fulltext_builds.front_mut()
        {
            build.stall = BUILD_STALL_BUDGET; // real progress: refill the budget.
        }
        // The chunk re-indexed committed text into the inverted index; raise the cross-snapshot
        // freshness marker to the store high-water so a reader whose snapshot predates this build
        // (and predates a covered node's current committed value, possibly written before the index
        // existed) declines to the always-correct scan path (`rmp` task #467). Only raises; never
        // clears a poison (an incremental build is not exhaustive — see
        // `bump_ft_spatial_marker_after_build`). Also discards the build's transient dirty flag so it
        // is not mis-attributed to the next user transaction.
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);

        if !done {
            return; // more of this build remains.
        }

        // (3) BELT AND BRACES: never publish into a WIPED index set (`rmp` task #733) — stall (bounded)
        // until the repair rebuild has run, then poison rather than promote.
        //
        // The cursor is deliberately NOT rewound here. Rewinding would make the *next* call re-run a
        // non-empty chunk, which the gap check would read as progress and use to refill the stall budget
        // — so the budget would be replenished faster than this gate spends it and the build would never
        // poison, spinning `LocalEngine::drain_index_builds` forever. Leaving the cursor at the end costs
        // nothing: the chunk's entries are already in the tree, and if the set is wiped again the epoch
        // check re-snapshots and rebuilds from scratch anyway.
        if self.index.borrow().is_degraded() {
            if Self::stall_or_poison(&mut builds.pending_fulltext_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut builds.pending_fulltext_builds,
                    &mut builds.poisoned_fulltext_builds,
                    &self.poison_events,
                );
            }
            return;
        }

        // (4) CONFLICT GATE (`rmp` task #778). Some chunk of this build skipped a node because an
        // in-flight writer held the newest version of a covered property. The snapshot is therefore NOT
        // fully indexed — promoting now would publish an index that is missing that node's committed text
        // and, worse, one whose terms no reader re-checks. Park the build with the writers that blocked
        // it and leave the index `Populating`, so every reader takes the snapshot-correct scan.
        //
        // The build is moved OFF the pending queue rather than rewound, for the termination reason the
        // degraded gate above documents: `LocalEngine::drain_index_builds` spins
        // `while has_pending_index_builds()`, so a build left pending while its blocking writer stays
        // open would spin the engine forever. `conflicted_fulltext_builds` is excluded from
        // `has_pending_index_builds`, exactly like the poison graveyard.
        //
        // It is deliberately NOT the poison graveyard: that is resurrected only by
        // `retry_poisoned_index_builds`, which on the threaded engine runs on the IDLE TICK and never on
        // the command path — and the tick's own gate does not count parked builds (`rmp` #763), so a
        // build parked there on an otherwise-idle engine is never resurrected at all. This queue is
        // drained from `advance_index_builds`, which every command drives.
        // BOTH conflict records are consulted, for the same reason gate (3) above re-checks `is_degraded`
        // rather than trusting this build's own history:
        //
        // - THIS build's `conflict_writers` — a node it personally skipped;
        // - the shared `ft_demoted_blockers` — a node the WHOLE-SET `rebuild_index` skipped.
        //
        // The second is not redundant. `rebuild_index` (run by any unrelated `CREATE INDEX` /
        // `CREATE CONSTRAINT` between this build's chunks) calls `IndexSet::clear`, which empties this
        // index's tree and refills it from the store — minus the entity it had to skip. `clear` does NOT
        // bump `wipe_generation` (only `fail_closed` does), so there is no epoch change and this build
        // does not re-snapshot: it simply resumes at its cursor. If the skipped entity sits BEFORE that
        // cursor the build never revisits it, finishes its remaining chunks cleanly, and — on its own
        // record alone — would promote `Online` over the hole, with the #467 marker already raised so
        // readers trust it. That is the #766 loss re-entering through the promotion door.
        let blocked_by_rebuild: Vec<TxnId> = self.index.borrow().ft_demoted_blockers().to_vec();
        if builds
            .pending_fulltext_builds
            .front()
            .is_some_and(|b| !b.conflict_writers.is_empty())
            || !blocked_by_rebuild.is_empty()
        {
            if let Some(mut build) = builds.pending_fulltext_builds.pop_front() {
                // Adopt the rebuild's blockers too, so this build is re-driven once EVERY writer that
                // holed it — its own and the rebuild's — has resolved.
                for w in blocked_by_rebuild {
                    if !build.conflict_writers.contains(&w) {
                        build.conflict_writers.push(w);
                    }
                }
                builds.conflicted_fulltext_builds.push(build);
            }
            return;
        }

        // The snapshot is fully indexed: durably flip the catalog entry to `Online`, then dequeue.
        // Read the current entry in its own scope so the store borrow is released before the write.
        let entry = self.store.borrow().fulltext_index(&name);
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let promoted = if let Some(entry) = entry {
            self.store.borrow_mut().set_fulltext_index(
                txn,
                name.clone(),
                FulltextIndexEntry {
                    state: IndexState::Online,
                    ..entry
                },
            );
            true
        } else {
            // The index was dropped mid-build; nothing to promote (the build will be dequeued).
            false
        };
        if promoted {
            if self.store.borrow_mut().commit(txn).is_err() {
                // The durable flip failed; leave the build pending `Populating` and retry next call.
                return;
            }
        } else {
            let _ = self.store.borrow_mut().rollback(txn);
        }
        self.index
            .borrow_mut()
            .set_fulltext_state(&name, IndexState::Online);
        builds.pending_fulltext_builds.pop_front();
    }

    /// Advances the front **spatial** build by up to `budget` nodes (`rmp` task #98), promoting +
    /// dequeuing it when complete. The spatial analogue of
    /// [`advance_fulltext_build`](Self::advance_fulltext_build): each chunk indexes a bounded number of
    /// snapshot nodes' point values into the grid via the shared
    /// [`index_one_node_spatial`](Self::index_one_node_spatial) helper, then on completion the named
    /// catalog entry is durably flipped to [`IndexState::Online`] (after which the planner begins
    /// routing proximity seeks to it).
    fn advance_spatial_build(&self, budget: usize) {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // (1) EPOCH CHECK + RE-SNAPSHOT — the spatial twin of `advance_node_property_build` (`rmp` #733).
        let generation = self.index.borrow().wipe_generation();
        if builds
            .pending_spatial_builds
            .front()
            .is_some_and(|b| b.generation != generation)
        {
            let Some(fresh) = Self::resnapshot_build(&self.store) else {
                Self::poison_front(
                    &mut builds.pending_spatial_builds,
                    &mut builds.poisoned_spatial_builds,
                    &self.poison_events,
                ); // poison: cannot re-base this build.
                return;
            };
            if let Some(build) = builds.pending_spatial_builds.front_mut() {
                build.snapshot = fresh;
                build.cursor = 0;
                build.generation = generation;
                build.stall = BUILD_STALL_BUDGET;
            }
        }
        let Some(build) = builds.pending_spatial_builds.front_mut() else {
            return;
        };
        let total = build.snapshot.len();
        let start = build.cursor;
        // `saturating_add` — see the node-property build's chunk bounds (`rmp` task #573): a `usize::MAX`
        // budget past a non-zero cursor would otherwise overflow and panic the engine thread.
        let end = total.min(build.cursor.saturating_add(budget));
        let chunk: Vec<u64> = build.snapshot[start..end].to_vec();
        let name = build.name.clone();
        let registered = [(build.label_token, build.prop_key)];
        build.cursor = end;
        let done = end >= total;

        // A clean slate: only THIS chunk's read faults may fail THIS build (`rmp` task #733).
        self.index.borrow_mut().clear_rebuild_gap();
        for id in chunk {
            Self::index_one_node_spatial(&self.store, &self.index, id, &registered);
        }
        // (2) GAP CHECK. A node this chunk could not read would be missing from the grid for good — the
        // residual `distance(...)` filter can drop a candidate but never add one back. Rewind and retry,
        // bounded by the stall budget so a persistent fault poisons the build (`rmp` task #733).
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            if Self::stall_or_poison(&mut builds.pending_spatial_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut builds.pending_spatial_builds,
                    &mut builds.poisoned_spatial_builds,
                    &self.poison_events,
                );
            } else if let Some(build) = builds.pending_spatial_builds.front_mut() {
                build.cursor = start;
            }
            // `rmp` #803: this rewind is AFTER the chunk loop, which raised the transient dirty flag.
            // Discard it rather than let the next unrelated write statement be charged with it.
            self.index.borrow_mut().clear_ft_spatial_dirty();
            return;
        }
        if end > start
            && let Some(build) = builds.pending_spatial_builds.front_mut()
        {
            build.stall = BUILD_STALL_BUDGET; // real progress: refill the budget.
        }
        // Raise the cross-snapshot freshness marker to the store high-water (read BEFORE the promotion
        // commit below so it reflects the indexed nodes' committed state, not the promotion txn's ts),
        // for the same reason as the full-text build: a reader whose snapshot predates this build must
        // decline to the scan path (`rmp` task #467). Only raises; never clears a poison. Also clears
        // the build's transient dirty flag.
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);

        if !done {
            return; // more of this build remains.
        }

        // (3) BELT AND BRACES: never publish into a WIPED index set (`rmp` task #733). The cursor is not
        // rewound — see `advance_fulltext_build` for why rewinding here defeats the stall budget.
        if self.index.borrow().is_degraded() {
            if Self::stall_or_poison(&mut builds.pending_spatial_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut builds.pending_spatial_builds,
                    &mut builds.poisoned_spatial_builds,
                    &self.poison_events,
                );
            }
            return;
        }

        // The snapshot is fully indexed: durably flip the catalog entry to `Online`, then dequeue.
        // Read the current entry in its own scope so the store borrow is released before the write.
        let entry = self.store.borrow().spatial_index(&name);
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        let promoted = if let Some(entry) = entry {
            self.store.borrow_mut().set_spatial_index(
                txn,
                name.clone(),
                SpatialIndexEntry {
                    state: IndexState::Online,
                    ..entry
                },
            );
            true
        } else {
            // The index was dropped mid-build; nothing to promote (the build will be dequeued).
            false
        };
        if promoted {
            if self.store.borrow_mut().commit(txn).is_err() {
                // The durable flip failed; leave the build pending `Populating` and retry next call.
                return;
            }
        } else {
            let _ = self.store.borrow_mut().rollback(txn);
        }
        self.index.borrow_mut().set_spatial_state(
            registered[0].0,
            registered[0].1,
            IndexState::Online,
        );
        builds.pending_spatial_builds.pop_front();
    }

    /// Drops the node-property index on `(label, property)` (`rmp` task #91): removes its durable
    /// catalog entry in a committed transaction and unregisters it from the in-memory [`IndexSet`],
    /// cancelling any in-progress non-blocking build of the same index.
    ///
    /// Idempotent on a never-declared index: the durable removal is a no-op and the in-memory
    /// unregister is a no-op, so dropping an absent index succeeds. The tokens are looked up (not
    /// interned): an unknown label/property means no such index can exist, so the call is a clean
    /// no-op success.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`, no
    /// such index) — the executor turns `false` into a `0` `indexes-removed` counter (`rmp` task #626
    /// follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_node_property_index(&self, label: &str, property: &str) -> Result<bool> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        // Resolve the tokens by lookup only; a missing token means the index cannot exist.
        let tokens = {
            let store = self.store.borrow();
            match (
                store.token_id(Namespace::Label, label),
                store.token_id(Namespace::PropKey, property),
            ) {
                // Only an actually-declared index is a real drop; tokens can exist with no index.
                (Some(label_token), Some(prop_key))
                    if store
                        .node_property_index_state(label_token, prop_key)
                        .is_some() =>
                {
                    Some((label_token, prop_key))
                }
                _ => None,
            }
        };
        let Some((label_token, prop_key)) = tokens else {
            return Ok(false); // no such index → clean no-op, nothing removed.
        };

        // Remove the durable catalog entry AND its name entry in one committed transaction (mirrors the
        // create path, which records both). Clearing the name alongside the index keeps the two in sync
        // and frees the name for reuse.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        {
            let store = self.store.borrow_mut();
            store.remove_node_property_index(txn, label_token, prop_key);
            store.remove_node_property_index_name_for(txn, label_token, prop_key);
        }
        self.store.borrow_mut().commit(txn)?;

        // Cancel any in-progress build for this index and unregister it from the in-memory set.
        //
        // The POISON GRAVEYARD is purged alongside the pending queue, and that is load-bearing, not
        // tidiness: a parked build outliving the drop of its own index is resurrected by
        // `retry_poisoned_index_builds` once the store reads cleanly, drains to the end, and its promotion
        // durably RE-CREATES the index this call just dropped — nameless, and surviving a restart, because
        // a reopen rebuilds the in-memory set from the catalog. `DROP INDEX` would be silently undone.
        Self::cancel_node_property_builds(
            &mut builds.pending_builds,
            &mut builds.poisoned_builds,
            label_token,
            prop_key,
        );
        self.index
            .borrow_mut()
            .unregister_node_property(label_token, prop_key);
        Ok(true) // an index was removed.
    }

    /// Drops the node-property index named `name` (`rmp` task #624), the `DROP INDEX <name>` surface:
    /// resolves the name to its covered `(label, property)`, removes the durable catalog + name entries
    /// in one committed transaction, cancels any in-progress build and unregisters it from the in-memory
    /// [`IndexSet`].
    ///
    /// `if_exists` controls the missing-name case: `true` (a `DROP INDEX <name> IF EXISTS`) makes a
    /// never-declared name a clean no-op success; `false` returns
    /// `Neo.ClientError.Schema.IndexDropFailed`.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`, an
    /// `IF EXISTS` drop of a missing name) — the executor turns `false` into a `0` `indexes-removed`
    /// counter (`rmp` task #626 follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` (no `IF EXISTS`) when no index of that name exists;
    /// - a storage error if the committing transaction fails.
    pub fn drop_node_property_index_by_name(&self, name: &str, if_exists: bool) -> Result<bool> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        let target = self.store.borrow().node_property_index_name(name);
        let Some((label_token, prop_key)) = target else {
            return if if_exists {
                Ok(false) // idempotent no-op: nothing removed.
            } else {
                Err(index_drop_not_found(name))
            };
        };

        // Remove the durable index catalog entry + its name in one committed transaction.
        let txn = self.mint_txn();
        self.store.borrow_mut().begin(txn);
        {
            let store = self.store.borrow_mut();
            store.remove_node_property_index(txn, label_token, prop_key);
            store.remove_node_property_index_name(txn, name);
        }
        self.store.borrow_mut().commit(txn)?;

        // Cancel any in-progress build for this index and unregister it from the in-memory set.
        //
        // The POISON GRAVEYARD is purged alongside the pending queue, and that is load-bearing, not
        // tidiness: a parked build outliving the drop of its own index is resurrected by
        // `retry_poisoned_index_builds` once the store reads cleanly, drains to the end, and its promotion
        // durably RE-CREATES the index this call just dropped — nameless, and surviving a restart, because
        // a reopen rebuilds the in-memory set from the catalog. `DROP INDEX` would be silently undone.
        Self::cancel_node_property_builds(
            &mut builds.pending_builds,
            &mut builds.poisoned_builds,
            label_token,
            prop_key,
        );
        self.index
            .borrow_mut()
            .unregister_node_property(label_token, prop_key);
        Ok(true) // an index was removed.
    }

    /// Lists every declared node-property index as `(name, label, property, state)` (`rmp` tasks #91,
    /// #624), for a `SHOW INDEXES` surface. Reads the durable catalog and resolves the tokens back to
    /// names; the index **name** is the durable name if recorded, else the deterministic
    /// [`auto_index_name`] (a defensive fallback for a not-yet-backfilled legacy index). An index whose
    /// tokens have no resolvable name (a defensively-skipped impossibility for a live token) is omitted.
    /// Ordered by the catalog's ascending `(label_token, prop_key)` key.
    #[must_use]
    pub fn list_node_property_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .node_property_indexes()
            .into_iter()
            .filter_map(|(label_token, prop_key, state)| {
                // The EFFECTIVE state (`rmp` task #733): a failed build / fail-closed leaves the durable
                // catalog saying ONLINE while the engine cannot use the index.
                let state = Self::effective_state(
                    state,
                    self.index
                        .borrow()
                        .node_property_state(label_token, prop_key),
                );
                let label = store.token_name(Namespace::Label, label_token)?;
                let property = store.token_name(Namespace::PropKey, prop_key)?;
                let name = store
                    .node_property_index_name_for(label_token, prop_key)
                    .unwrap_or_else(|| auto_index_name(&label, &property));
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// The physical planner's [`IndexCatalog`] reflecting the indexes this coordinator currently
    /// holds (`rmp` task #48, `04 §6.6`): a token-lookup entry for every label that has at least one
    /// indexed node, and a single-property entry for every **`Online`** node-property index. Tokens
    /// with no resolvable name (a defensively-skipped impossibility for a live token) are omitted.
    ///
    /// # State gating (`rmp` task #90)
    ///
    /// Only an [`IndexState::Online`] node-property index is surfaced to the planner: a `Populating`
    /// one is **withheld** so the planner never routes a seek to a half-built index — it falls back to
    /// a label-scan + filter for that `(label, property)` until the index is promoted. The filtering
    /// happens here ([`IndexSet::online_node_properties`]), so the `IndexCatalog` only ever contains
    /// usable indexes and the physical planner needs no state awareness — the lowest-friction path.
    /// The token-lookup (label) entries are unaffected: they come from the always-present label index,
    /// not from any declared node-property index.
    pub fn catalog(&self) -> IndexCatalog {
        let mut builder = IndexCatalog::builder();
        // ### A ~160-line store borrow, and why it is sound (`rmp` #1010)
        //
        // This guard is alive for the whole method, across a dozen `self.index.borrow…()` acquisitions
        // and eight `for` headers. Sound because the two are **different cells**: nothing in this
        // method re-acquires `store`, and every loop body reads only through this guard. `store` is
        // used exclusively for `token_name` / `composite_indexes` / `rel_composite_indexes`, all
        // inherent `RecordStore` reads with no path back to the coordinator.
        //
        // Two details that would matter if this method were edited:
        //
        // * The eight `for … in self.index.borrow…()` headers each hold an *index* guard for their
        //   whole loop body (a `for`'s iterator expression outlives the loop, unlike an `if`
        //   condition's temporaries). That is why no body may touch the index — only `store`, as they
        //   all do today.
        // * Resolving a token therefore costs no re-acquisition; that is the point of hoisting the
        //   borrow here rather than taking it per lookup.
        let store = self.store.borrow();

        // The label (token-lookup) index, but only while it may be trusted: a rebuild whose store scan
        // faulted leaves it empty, and the seam then enumerates the store instead (`rmp` task #733), so
        // advertising an index the engine will not use would only mislead the planner's costing.
        if self.index.borrow().labels_usable() {
            for token in self.index.borrow_mut().indexed_label_tokens() {
                if let Some(name) = store.token_name(Namespace::Label, token) {
                    builder = builder.with_token_lookup(name);
                }
            }
        }
        for (label_token, prop_key) in self.index.borrow().online_node_properties() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_property(label, property);
        }
        // Spatial indexes (`rmp` task #73): surface every **`Online`** spatial index so the physical
        // planner can route a proximity predicate to a `SpatialIndexSeek`. Like node-property indexes,
        // only `Online` ones are exposed (`online_spatial` filters by state), so a half-built spatial
        // index never drives a seek — the planner keeps the scan + filter until it is promoted.
        for (label_token, prop_key) in self.index.borrow().online_spatial() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_spatial(label, property);
        }
        // Text (trigram) indexes (`rmp` task #662): surface every **`Online`** text index so the
        // physical planner can route a `CONTAINS` / `ENDS WITH` / `STARTS WITH` predicate to a
        // `NodeTextIndexSeek`. Like the other kinds only `Online` ones are exposed (`online_text` filters
        // by state), so a half-built text index never drives a seek — the planner keeps the scan + filter
        // until it is promoted; the backing trigram index exists in the in-memory set (registered on open
        // / create), so the seek the planner emits always finds it.
        for (label_token, prop_key) in self.index.borrow().online_text() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_text(label, property);
        }
        // Standalone composite (multi-property) node indexes (`rmp` task #657): surface every
        // **`Online`** one so the physical planner can consume a leading run of equality conjuncts into
        // one composite `NodeIndexSeek`. Read from the **durable** catalog (the source of a standalone
        // composite's registration), filtered to `Online` — a `Populating` one is withheld exactly like a
        // half-built single-property index. The backing tree exists in the in-memory set (registered on
        // open / create), so the seek the planner emits always finds it.
        for (_name, entry) in store.composite_indexes() {
            if entry.state != IndexState::Online {
                continue;
            }
            let Some(label) = store.token_name(Namespace::Label, entry.label_token) else {
                continue;
            };
            let mut properties = Vec::with_capacity(entry.property_tokens.len());
            let mut resolvable = true;
            for pk in &entry.property_tokens {
                match store.token_name(Namespace::PropKey, *pk) {
                    Some(p) => properties.push(p.to_owned()),
                    None => {
                        resolvable = false;
                        break;
                    }
                }
            }
            if resolvable {
                builder = builder.with_label_composite(label, properties);
            }
        }
        // Relationship-property indexes (`rmp` task #659): surface every **`Online`** rel-property index
        // so the physical planner can route a `MATCH ()-[r:T {p: v}]-()` / `WHERE r.p = v` equality to a
        // `RelIndexSeek` instead of scanning every `:T` relationship and filtering. Only `Online` ones are
        // exposed (`online_rel_properties` filters by state), so a half-built index never drives a seek —
        // the planner keeps the scan + filter until it is promoted; the backing tree exists in the
        // in-memory set (registered on open / create), so the seek the planner emits always finds it.
        for (type_token, prop_key) in self.index.borrow().online_rel_properties() {
            let (Some(rel_type), Some(property)) = (
                store.token_name(Namespace::RelType, type_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_rel_property(rel_type, property);
        }
        // Relationship spatial (point) indexes (`rmp` task #664): surface every **`Online`** relationship
        // spatial index so the physical planner can route a `MATCH ()-[r:T]-() WHERE distance(r.p, $c) <=
        // $d` proximity to a `RelSpatialIndexSeek` instead of scanning every `:T` relationship. Only
        // `Online` ones are exposed (`online_spatial_rel` filters by state); relationship spatial indexes
        // are created synchronous-`Online`, so this is always the full set. The backing grid exists in the
        // in-memory set (registered on open / create), so the seek the planner emits always finds it.
        for (type_token, prop_key) in self.index.borrow().online_spatial_rel() {
            let (Some(rel_type), Some(property)) = (
                store.token_name(Namespace::RelType, type_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_rel_spatial(rel_type, property);
        }
        // Standalone composite (multi-property) relationship indexes (`rmp` task #666): surface every
        // **`Online`** one so the physical planner can consume a leading run of equality conjuncts on a
        // relationship variable into one `RelCompositeIndexSeek` (or serve its leading key as a
        // single-key `RelIndexSeek`). Read from the **durable** catalog filtered to `Online`, exactly
        // like the node composite surface above; the backing tree exists in the in-memory `rel_composite`
        // map (registered on open / create), so the seek the planner emits always finds it.
        for (_name, entry) in store.rel_composite_indexes() {
            if entry.state != IndexState::Online {
                continue;
            }
            let Some(rel_type) = store.token_name(Namespace::RelType, entry.type_token) else {
                continue;
            };
            let mut properties = Vec::with_capacity(entry.property_tokens.len());
            let mut resolvable = true;
            for pk in &entry.property_tokens {
                match store.token_name(Namespace::PropKey, *pk) {
                    Some(p) => properties.push(p.to_owned()),
                    None => {
                        resolvable = false;
                        break;
                    }
                }
            }
            if resolvable {
                builder = builder.with_rel_composite(rel_type, properties);
            }
        }
        // Vector (HNSW) indexes (`rmp` task #669): surface every **`Online`** node / relationship vector
        // index so the query planner (`rmp` #671) can route a k-NN query to a vector index seek. Only
        // `Online` ones are exposed (`online_vector` / `online_vector_rel` filter by state); vector
        // indexes are created synchronous-`Online`, so this is always the full set. The backing HNSW
        // graph exists in the in-memory set (registered on open / create), so the seek the planner emits
        // always finds it. Without this surfacing the planner (#671) would never see the index — the
        // #659 trap.
        for (label_token, prop_key) in self.index.borrow().online_vector() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_vector(label, property);
        }
        for (type_token, prop_key) in self.index.borrow().online_vector_rel() {
            let (Some(rel_type), Some(property)) = (
                store.token_name(Namespace::RelType, type_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_rel_vector(rel_type, property);
        }
        builder.build()
    }

    /// A compile-time [`Statistics`] source over this coordinator's shared store (`rmp` task #82),
    /// for [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats).
    ///
    /// This is how the production compile paths (the server's per-`Run` compile, the TCK runner,
    /// the LDBC bench driver) activate the cost-based optimiser: they hold no statement seam while
    /// compiling, so the per-statement [`RecordStoreGraph::statistics`](crate::graph_access::GraphAccess::statistics)
    /// seam is unavailable — this one answers from the same durable catalogue without needing an
    /// open transaction. See [`CoordinatorStatistics`] for the snapshot and borrow contracts.
    #[must_use]
    pub fn statistics(&self) -> CoordinatorStatistics<D, S> {
        CoordinatorStatistics {
            store: self.store.clone(),
        }
    }

    /// Borrows a per-statement [`RecordStoreGraph`] seam for the open transaction `txn`: the executor
    /// runs over it, its reads/writes contribute SIREAD markers / rw-edges to the
    /// shared trackers, and it is dropped when the statement ends (the transaction stays open).
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    ///
    /// `D`/`S` carry `Send + Sync + 'static` because the returned seam can hand the executor an
    /// off-thread morsel read view (`rmp` task #339); every real store instantiation already meets these
    /// bounds (the `rmp` #336 off-thread reader path requires the same).
    pub fn statement(&self, txn: TxnId) -> Result<RecordStoreGraph<D, S>>
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        let snapshot = self
            .with_active(|a| a.get(&txn).map(|t| t.snapshot))
            .ok_or_else(|| {
                GraphusError::Transaction(format!("statement in inactive txn {}", txn.0))
            })?;
        Ok(RecordStoreGraph::attach(
            self.store.clone(),
            txn,
            snapshot,
            self.ssi.clone(),
            self.index.clone(),
            self.columns.clone(),
            self.zones.clone(),
            self.csr.clone(),
        ))
    }

    /// Captures, **on the engine thread**, the owned `Send` pieces an off-thread reader needs to run a
    /// read-only statement for the open transaction `txn` against a
    /// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) — without holding any `Rc`/`RefCell`
    /// across the thread boundary (`rmp` task #336, Slice 3b-ii).
    ///
    /// The returned [`ReadTaskInputs`] bundles: a [`StoreReadView`] (`Arc`-shared page cache + an owned
    /// [`MetaSnapshot`](graphus_storage::MetaSnapshot) of the committed location metadata), a
    /// [`TokenSnapshot`] (the `id ↔ name` dictionary), this reader's MVCC read [`Snapshot`], a **clone**
    /// of the store's [`CommitRegistry`] (so the reader resolves an in-flight writer to its outcome
    /// independently of the live store), and a **fresh, empty** [`SsiReadBuffer`] tagged with `txn` for
    /// the reader to accumulate its SIREAD markers into.
    ///
    /// Because `txn` was registered with the SSI tracker and inserted into the active set at
    /// [`begin`](Self::begin) — which happens **before** this capture and the subsequent dispatch — a
    /// concurrent writer's `record_write` always sees `txn` in `ssi.txns` and forms any rw-edge against
    /// it; and `txn` keeps pinning [`oldest_active_snapshot`](Self::oldest_active_snapshot) (so GC
    /// cannot reclaim a version the reader still needs) until it is removed at retirement
    /// (commit/rollback on the engine thread). The capture itself only **reads** the store (append-only
    /// `device_pages` + monotonic `high_water`), so it is MVCC-superset-safe.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    /// Demotes a standalone auto-commit read-only transaction to **Snapshot Isolation** (`rmp` task
    /// #545): it stops participating in SSI serializability tracking — [`merge_read_buffer`] drops its
    /// SIREAD markers unmerged and [`commit`](Self::commit) skips `detect_pivot_abort` (via
    /// [`IsolationLevel::runs_ssi`] returning `false`) — so a read carries no serializability overhead
    /// and can never cause a writer to abort. This is the MySQL / MariaDB / SQL-Server model: a
    /// standalone read is an SI snapshot read, not a serializable transaction.
    ///
    /// The transaction KEEPS its active-set snapshot reservation, so it still pins the GC watermark
    /// ([`oldest_active_snapshot`](Self::oldest_active_snapshot)) for the versions it reads (the InnoDB
    /// read-view analogue) — reads remain lock-free and observe a consistent MVCC snapshot with no
    /// premature reclamation (the #220 invariant).
    ///
    /// A no-op if `txn` is not open. The engine applies it ONLY to auto-commit read-only statements
    /// (both the off-thread reader path and the inline fallback), so the isolation is identical however
    /// the read is dispatched; explicit user transactions (`BEGIN … COMMIT`) and every write keep full
    /// Serializable SSI.
    pub fn demote_read_to_snapshot(&self, txn: TxnId) {
        // The demotion is recorded under the hold and the SSI tracker told after it: the hold
        // covers this table only, and `mark_snapshot` takes a different lock.
        let demoted = self.with_active(|a| {
            a.get_mut(&txn).map(|t| {
                t.isolation = IsolationLevel::Snapshot;
            })
        });
        if demoted.is_some() {
            self.ssi.borrow_mut().mark_snapshot(txn);
        }
    }

    pub fn read_task_inputs(&self, txn: TxnId) -> Result<ReadTaskInputs<D, S>> {
        // `rmp` #973: the snapshot an off-thread read task carries away, together with the page map
        // and token snapshot it will read through. Everything the task later sees is fixed here.
        graphus_core::sched::yield_at(
            graphus_core::sched::YieldSite::SnapshotReadTaskInputs,
            graphus_core::sched::ResourceId::txn(txn.0),
        );
        let snapshot = self
            .with_active(|a| a.get(&txn).map(|t| t.snapshot))
            .ok_or_else(|| {
                GraphusError::Transaction(format!("read dispatch for inactive txn {}", txn.0))
            })?;
        let store = self.store.borrow();
        Ok(ReadTaskInputs {
            view: store.read_view(),
            tokens: store.token_snapshot(),
            snapshot,
            registry: store.commit_registry_snapshot(),
            buffer: SsiReadBuffer::new(txn),
            // `rmp` #546: capture the full-text catalogue so an off-thread `db.index.fulltext.
            // queryNodes` resolves the index by name and recomputes matches from this snapshot. Small
            // (one entry per declared index) and usually empty, so a per-read `Arc`-free clone is
            // negligible.
            fulltext: self.index.borrow().fulltext_snapshot(),
            // Filled by the dispatch site via `index_candidates_for` (it needs the plan + bound
            // parameters, which this method does not take). Defaulting to empty here keeps every other
            // caller — the DST harness, the tests — on the pre-#755 behaviour: a miss declines to the
            // exact scan.
            index_candidates: crate::read_source::IndexCandidateCapture::default(),
            // Left empty here for the same reason as `index_candidates`: only the dispatch site holds
            // the plan that says which counts are wanted. An unfilled memo declines to the scan.
            count_store: crate::read_source::CountStoreCapture::default(),
        })
    }

    /// Pre-runs, on the engine thread, every node-property equality seek `plan` will ask for whose seek
    /// value is statically knowable from `params`, and returns the `Send + Sync` memo of their results
    /// for an off-thread reader (`rmp` task #755, Slice S2).
    ///
    /// This is the whole of the engine thread's contribution to an off-thread index seek: **raw
    /// candidate ids and nothing else**. Every scrap of semantics — MVCC visibility, the label
    /// re-check, the current-value residual, the SIREAD markers, the dedup — stays with the reader, which
    /// runs it through the same lifted [`read_source::index_seek_eq_recheck`] body the live inline path
    /// uses. So serving a seek off-thread cannot drift from serving it inline: past the candidate list,
    /// it is literally the same code.
    ///
    /// Correctness rests on the memo being a **superset** of the reader's true matches, argued in full
    /// on [`IndexCandidateCapture`](crate::read_source::IndexCandidateCapture) (the reader's snapshot
    /// precedes this capture; the node-property index is append-only per entry; the capture is atomic
    /// against index mutation because both run on this one serial thread). The gates that keep it a
    /// superset live in [`IndexSet::capture_node_property_eq`](crate::index_set::IndexSet::capture_node_property_eq).
    ///
    /// Cheap and self-limiting: it runs at most one seek per `NodeIndexSeek` operator in the plan
    /// (almost always exactly one, usually zero — most reads seek no index), each the very seek the
    /// statement was going to run anyway. It is not extra work; it is the *same* work, moved to the
    /// thread that owns the index.
    #[must_use]
    pub fn index_candidates_for(
        &self,
        txn: TxnId,
        plan: &crate::physical::PhysicalPlan,
        params: &crate::binding::BoundParameters,
    ) -> crate::read_source::IndexCandidateCapture {
        // Every node- and relationship-property seek kind the reader can be served off-thread (`rmp` #755
        // node equality + `rmp` #768 node range/composite/text + `rmp` #769 rel equality/range/composite).
        // Correlated per-row seeks are excluded by construction (only a literal or bound parameter is
        // statically knowable — `rmp` #764).
        let eq_seeks = plan.static_node_index_eq_seeks(params);
        let range_seeks = plan.static_node_index_range_seeks(params);
        let composite_seeks = plan.static_node_composite_seeks(params);
        let text_seeks = plan.static_node_text_seeks(params);
        let rel_eq_seeks = plan.static_rel_index_eq_seeks(params);
        let rel_range_seeks = plan.static_rel_index_range_seeks(params);
        let rel_composite_seeks = plan.static_rel_composite_seeks(params);
        // Spatial (point) seeks take no `params`: their centre + radius are plan-time-folded constants
        // (`rmp` #770). VECTOR is deliberately NOT captured — `db.index.vector.*` runs inline (not
        // reader-safe), so an ANN read never dispatches off-thread.
        let spatial_seeks = plan.static_node_spatial_seeks();
        let rel_spatial_seeks = plan.static_rel_spatial_seeks();
        if eq_seeks.is_empty()
            && range_seeks.is_empty()
            && composite_seeks.is_empty()
            && text_seeks.is_empty()
            && rel_eq_seeks.is_empty()
            && rel_range_seeks.is_empty()
            && rel_composite_seeks.is_empty()
            && spatial_seeks.is_empty()
            && rel_spatial_seeks.is_empty()
        {
            return crate::read_source::IndexCandidateCapture::default();
        }
        // The reader's own snapshot decides whether a captured seek may be trusted at all (the rebuild
        // gate — `rmp` #755/#768, containing / closing `rmp` #765). An unknown txn captures nothing.
        let Some(reader_ts) = self.with_active(|a| a.get(&txn).map(|t| t.snapshot.ts)) else {
            return crate::read_source::IndexCandidateCapture::default();
        };
        // Resolve names → tokens through the live store, exactly as the inline seek does. A label or
        // property key that was never interned cannot match any node, so it simply yields no request
        // (the reader misses and declines to its scan, which returns the same empty result).
        //
        // ### An ~85-line store borrow, and why it is sound (`rmp` #1010)
        //
        // The guard covers nine `filter_map` passes and is released by the explicit `drop(store)` below
        // before the index is acquired — so `store` and `index` are never held together here, even
        // though they are different cells and holding both would be legal.
        //
        // Sound because nothing inside re-acquires `store`: every closure calls only `store.token_id`,
        // an inherent `RecordStore` read, through this guard. The early returns above all happen
        // *before* the guard is taken, so no path leaves it held across a `?`; the passes themselves are
        // infallible (`filter_map`, never `?`), which is what keeps the `drop` reachable on every path.
        //
        // The `drop` is load-bearing, not stylistic: the guard would otherwise live to the end of the
        // function and overlap the `index` acquisition. That overlap is harmless *today* (two different
        // cells, one thread), but holding two coordinator cells at once is the raw material of a
        // lock-order cycle the moment layers 3-7 admit a second writer. Keeping the acquisitions
        // disjoint costs nothing and removes the question.
        let store = self.store.borrow();
        let eq_requests: Vec<(u32, u32, Value)> = eq_seeks
            .into_iter()
            .filter_map(|(label, property, value)| {
                let label_token = store.token_id(Namespace::Label, &label)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((label_token, prop_key, value))
            })
            .collect();
        let range_requests: Vec<crate::index_set::RangeCaptureRequest> = range_seeks
            .into_iter()
            .filter_map(|(label, property, lower, upper)| {
                let label_token = store.token_id(Namespace::Label, &label)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((label_token, prop_key, lower, upper))
            })
            .collect();
        let composite_requests: Vec<crate::index_set::CompositeCaptureRequest> = composite_seeks
            .into_iter()
            .filter_map(|(label, properties, values)| {
                let label_token = store.token_id(Namespace::Label, &label)?;
                let property_tokens: Option<Vec<u32>> = properties
                    .iter()
                    .map(|p| store.token_id(Namespace::PropKey, p))
                    .collect();
                Some((label_token, property_tokens?, values))
            })
            .collect();
        let text_requests: Vec<crate::index_set::TextCaptureRequest> = text_seeks
            .into_iter()
            .filter_map(|(label, property, op, needle)| {
                let label_token = store.token_id(Namespace::Label, &label)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((label_token, prop_key, op, needle))
            })
            .collect();
        // Relationship seeks resolve the type through the `RelType` namespace (`rmp` #769); the property
        // namespace is shared with nodes.
        let rel_eq_requests: Vec<(u32, u32, Value)> = rel_eq_seeks
            .into_iter()
            .filter_map(|(rel_type, property, value)| {
                let type_token = store.token_id(Namespace::RelType, &rel_type)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((type_token, prop_key, value))
            })
            .collect();
        let rel_range_requests: Vec<crate::index_set::RangeCaptureRequest> = rel_range_seeks
            .into_iter()
            .filter_map(|(rel_type, property, lower, upper)| {
                let type_token = store.token_id(Namespace::RelType, &rel_type)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((type_token, prop_key, lower, upper))
            })
            .collect();
        let rel_composite_requests: Vec<crate::index_set::CompositeCaptureRequest> =
            rel_composite_seeks
                .into_iter()
                .filter_map(|(rel_type, properties, values)| {
                    let type_token = store.token_id(Namespace::RelType, &rel_type)?;
                    let property_tokens: Option<Vec<u32>> = properties
                        .iter()
                        .map(|p| store.token_id(Namespace::PropKey, p))
                        .collect();
                    Some((type_token, property_tokens?, values))
                })
                .collect();
        // Spatial (point) seeks (`rmp` #770): node keyed through the `Label` namespace, rel through
        // `RelType`; the property namespace is shared. The centre/radius stay `f64` — no encoding here.
        let spatial_requests: Vec<crate::index_set::SpatialCaptureRequest> = spatial_seeks
            .into_iter()
            .filter_map(|(label, property, cx, cy, r)| {
                let label_token = store.token_id(Namespace::Label, &label)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((label_token, prop_key, cx, cy, r))
            })
            .collect();
        let rel_spatial_requests: Vec<crate::index_set::SpatialCaptureRequest> = rel_spatial_seeks
            .into_iter()
            .filter_map(|(rel_type, property, cx, cy, r)| {
                let type_token = store.token_id(Namespace::RelType, &rel_type)?;
                let prop_key = store.token_id(Namespace::PropKey, &property)?;
                Some((type_token, prop_key, cx, cy, r))
            })
            .collect();
        // One `borrow_mut`, nine per-kind captures merged into one memo. RANGE/COMPOSITE (node and rel)
        // and equality ride the shared rebuild watermark; TEXT and SPATIAL ride the ft/spatial marker.
        let mut index = self.index.borrow_mut();
        let mut capture = index.capture_node_property_eq(reader_ts, &eq_requests);
        capture.absorb(index.capture_node_property_range(reader_ts, &range_requests));
        capture.absorb(index.capture_node_property_composite(reader_ts, &composite_requests));
        capture.absorb(index.capture_node_property_text(reader_ts, &text_requests));
        capture.absorb(index.capture_rel_property_eq(reader_ts, &rel_eq_requests));
        capture.absorb(index.capture_rel_property_range(reader_ts, &rel_range_requests));
        capture.absorb(index.capture_rel_composite(reader_ts, &rel_composite_requests));
        capture.absorb(index.capture_node_spatial(reader_ts, &spatial_requests));
        capture.absorb(index.capture_rel_spatial(reader_ts, &rel_spatial_requests));
        capture
    }

    /// Captures, on the engine thread, the **count-store answers** `plan` will ask for on a reader
    /// thread (`rmp` task #866) — or an empty capture, which makes every lookup miss and the reader
    /// fall back to the `Aggregation`-over-scan subtree.
    ///
    /// This is the off-thread half of the count-store access path. The inline seam
    /// ([`RecordStoreGraph::count_store_nodes`](crate::record_graph::RecordStoreGraph)) proves its
    /// equivalence predicate and reads the counter in one borrow on this same thread; a reader thread
    /// can do neither — it holds no live store, and the predicate is about *this* thread's current
    /// state. So the verdict and the values are frozen together here, at dispatch, at an instant at
    /// which the predicate provably held.
    ///
    /// The predicate is the same three conjuncts, for the same reasons, and is documented in full on
    /// `RecordStoreGraph::count_store_equivalent`:
    ///
    /// * **E1** no transaction holds a pending count delta ([`RecordStore::counts_match_committed_image`])
    ///   — the counters move eagerly at write time, so an in-flight writer's rows are already in them;
    /// * **E2** nothing has committed since this reader's snapshot (`snapshot_ts() == snapshot.ts`);
    /// * **E3** the reader is Snapshot-isolated, so its (absent) SIREAD markers are discarded anyway.
    ///
    /// E3 is guaranteed at this call site — only a structurally read-only auto-commit statement is
    /// dispatched off-thread, and it was demoted before dispatch — but it is **checked**, not assumed:
    /// a future caller that dispatched a Serializable read would otherwise silently narrow its read
    /// footprint, and this function has no way to know it happened.
    #[must_use]
    pub fn count_store_for(
        &self,
        txn: TxnId,
        plan: &crate::physical::PhysicalPlan,
    ) -> crate::read_source::CountStoreCapture {
        let mut capture = crate::read_source::CountStoreCapture::default();
        let (node_requests, rel_requests) = plan.count_store_requests();
        if node_requests.is_empty() && rel_requests.is_empty() {
            return capture;
        }
        // An unknown transaction cannot have a snapshot to be equivalent to; decline.
        let Some(active) = self.with_active(|a| a.get(&txn).copied()) else {
            return capture;
        };
        // E3, keyed on `SsiTracker::is_snapshot` — the SAME predicate the inline seam uses
        // (`RecordStoreGraph::count_store_equivalent`), and deliberately NOT `isolation.runs_ssi()`.
        //
        // The two are not the same set, and the difference is a real hole (`rmp` #866). What makes
        // answering with zero SIREAD markers sound is that the reader's buffer is DROPPED by
        // `SsiTracker::merge_read_buffer`, which gates on `snapshot_txns` membership — i.e. on
        // `is_snapshot`, nothing else. `demote_read_to_snapshot` sets both the per-transaction
        // isolation and that membership, so for a demoted auto-commit read the two agree; but
        // `begin(IsolationLevel::Snapshot)` sets only the isolation, and such a reader's markers ARE
        // merged. Gating on the isolation alone would hand it a count with no markers, dropping an
        // rw-edge and preventing a Serializable pivot's abort — a transaction SSI would have aborted
        // would commit instead. No server path reaches it today (`AccessMode::isolation()` returns
        // `Serializable` unconditionally), but both this method and `begin` are public, so the
        // predicate must be right by construction rather than by who happens to call it.
        //
        // It is also the stronger gate for the case that IS live: a reader-safe procedure read is
        // dispatched off-thread but deliberately NOT demoted (`rmp` #548), so it keeps full
        // Serializable SSI. `runs_ssi()` happened to decline it; `is_snapshot()` declines it because it
        // is genuinely not in `snapshot_txns`, which is the reason that actually matters.
        if !self.ssi.borrow().is_snapshot(txn) {
            return capture;
        }
        let store = self.store.borrow();
        if store.snapshot_ts() != active.snapshot.ts || !store.counts_match_committed_image() {
            return capture;
        }
        for label in node_requests {
            let count = match label.as_deref() {
                Some(l) => crate::store_statistics::nodes_with_label(store, l),
                None => store.total_node_count(),
            };
            capture.insert_nodes(label, count);
        }
        for types in rel_requests {
            // Sum over the (already deduplicated) types — a relationship carries exactly one type — and
            // read the grand total for the "any type" request.
            let count = if types.is_empty() {
                store.total_relationship_count()
            } else {
                types
                    .iter()
                    .map(|t| crate::store_statistics::relationships_with_type(store, t))
                    .sum()
            };
            capture.insert_rels(types, count);
        }
        capture
    }

    /// Breaks the dangerous structure [`SsiTracker::detect_pivot_abort`] found while committing `txn`,
    /// having chosen `victim` (`04 §5.4`). The single door both [`commit`](Self::commit) and
    /// [`commit_prepare`](Self::commit_prepare) go through.
    ///
    /// Returns `Ok(())` when the structure is broken and `txn` may go on to commit, and a **retriable**
    /// [`GraphusError::Transaction`] when `txn` itself was the transaction that had to abort — in which
    /// case it has already been rolled back here.
    ///
    /// # This transaction is undone here; another transaction never is (`rmp` #1051)
    ///
    /// When `victim == txn` the undo runs inline: `txn` is this worker's own transaction and this
    /// thread is the only one inside it.
    ///
    /// When `victim != txn` the victim belongs to **another engine worker** (`D-multi-writer`), which
    /// may at this instant be executing a statement in it, committing it, or already rolling it back.
    /// This used to call `abort(victim)` regardless, and at `engine_workers = 8` that put two workers
    /// inside `RecordStore::rollback_logical` for one transaction at the same time: the first detached
    /// and freed its deltas and its commit slot, the second walked a chain those deltas had already
    /// left, and the store's head-prefix tripwire refused — leaving the transaction OPEN with its
    /// uncommitted writes physically present and taking the database to its degraded state. The engine
    /// states the same rule for its age sweep and declines a sibling's transaction on it (`maybe_reap_aged`,
    /// `rmp` #1041). So the victim is **condemned** ([`SsiTracker::doom`]) and aborts itself, at its own
    /// commit, on its own worker — PostgreSQL's model exactly (`predicate.c`: "we flag the writer for
    /// termination, causing it to abort when it tries to commit").
    ///
    /// # And when the condemnation cannot take, this transaction commits suicide
    ///
    /// A condemnation only takes if the victim will actually consult it: it must still be open in the
    /// tracker ([`SsiTracker::doom`] reports that) **and** its own commit must run SSI validation,
    /// which an [`IsolationLevel::Snapshot`] transaction does not. If either fails, the structure is
    /// broken the only other way that never touches a foreign transaction — `txn` aborts instead. That
    /// is PostgreSQL's own escape hatch for a pivot it cannot kill: "Normally, we kill the pivot
    /// transaction to make sure we make progress if the failing transaction is retried. However, we
    /// can't kill it if it's already prepared, so in that case we commit suicide instead"
    /// (`PreCommit_CheckForSerializationFailure`, read 2026-08-11). It costs the guarantee nothing and
    /// only the forward-progress preference, on a path the server cannot reach: every transaction the
    /// server begins is `Serializable`, and the one demotion to `Snapshot` (`rmp` #545) applies to
    /// read-only auto-commit statements, which write nothing and so can never be a pivot.
    fn break_dangerous_structure(&self, txn: TxnId, victim: TxnId) -> Result<()> {
        let condemned = victim != txn
            && self
                .with_active(|a| a.get(&victim).map(|t| t.isolation))
                .is_some_and(IsolationLevel::runs_ssi)
            && self.ssi.borrow_mut().doom(victim);
        if condemned {
            return Ok(());
        }
        self.abort(txn)?;
        Err(GraphusError::Transaction(format!(
            "serialization failure: transaction {} aborted to preserve serializability (SSI \
             dangerous structure); retry",
            txn.0
        )))
    }

    /// Merges an off-thread reader's accumulated [`SsiReadBuffer`] into the shared
    /// [`SsiTracker`](graphus_txn::SsiTracker) on the engine thread, replaying its SIREAD markers
    /// (sorted + deduped) so the conflict graph is byte-identical to recording them inline (`rmp` tasks
    /// #341 + #336, Slice 3b-ii).
    ///
    /// **This is the M1 serializability barrier.** The engine MUST call this for a retiring reader
    /// **before** it runs [`commit`](Self::commit) for that reader (or for any concurrent writer whose
    /// pivot detection could depend on the reader's edges) — i.e. the merge is the first step of closing
    /// the reader. Because the merge and every [`commit`](Self::commit)'s `detect_pivot_abort` both run
    /// under the tracker's own lock — exclusivity, not one serial event stream — the no-lost-edge proof
    /// is M1' rather than in-order event processing: a reader's merge only touches edges incident on
    /// that reader, so the order in which distinct readers are merged is unobservable (`rmp` #1039; the
    /// proof is written out at `graphus_server::engine::finish_reader`). Calling it for a still-open
    /// `txn` simply folds the markers in; it does not commit or remove the transaction.
    pub fn merge_read_buffer(&self, buffer: SsiReadBuffer) {
        self.ssi.borrow_mut().merge_read_buffer(buffer);
    }

    /// Commits `txn`: runs SSI validation (SERIALIZABLE only, aborting a pivot on a dangerous
    /// structure), then commits it on the store (assign commit timestamp, settle MVCC headers, WAL
    /// group-commit) and publishes the SSI outcome. Returns the commit timestamp.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not open.
    /// - [`GraphusError::Transaction`] (retriable serialization failure) if `txn` is chosen as the
    ///   SSI abort victim — it is rolled back and the caller should retry.
    /// - A storage error if the store commit fails.
    pub fn commit(&self, txn: TxnId) -> Result<Timestamp> {
        let isolation = self
            .with_active(|a| a.get(&txn).map(|t| t.isolation))
            .ok_or_else(|| {
                GraphusError::Transaction(format!("commit of inactive txn {}", txn.0))
            })?;

        // 1) SSI validation (SERIALIZABLE only): abort a pivot on a dangerous structure (`04 §5.4`).
        if isolation.runs_ssi() {
            let victim = self.ssi.borrow().detect_pivot_abort(txn);
            if let Some(victim) = victim {
                self.break_dangerous_structure(txn, victim)?;
            }
        }

        // 2) Commit on the store: it assigns the commit timestamp, settles MVCC headers and group-
        //    commits the WAL (`rmp` task #45). The store is the timestamp oracle, so the commit
        //    timestamp is its post-commit snapshot high-water.
        // The store RETURNS the timestamp it assigned (`rmp` #1056). Re-reading `snapshot_ts()` here
        // was correct only while one thread could be committing: under `D-multi-writer` it returns
        // whatever the clock says at that instant — a sibling worker's commit timestamp, or (since the
        // horizon now lags an in-flight commit) a timestamp BELOW this transaction's own. Either way
        // the value fed to `ssi.record_commit` below would not be this transaction's commit timestamp,
        // and every `are_concurrent` decision involving it would be answered against a fiction.
        let commit_ts = self.store.borrow_mut().commit(txn)?;

        // Authoritative cross-snapshot freshness stamp (`rmp` task #467): if `txn` structurally
        // mutated a full-text/spatial posting (recorded by the statement seam during its writes), retire
        // it as a committed mutator and raise the marker to `commit_ts`. From `commit_ts` onward the
        // change is committed-visible in BOTH the index and the scan, so a reader at-or-after it may
        // trust the fast index path; an older reader correctly declines. Because the in-flight set is
        // keyed by txn, the effective marker stays `u64::MAX` until EVERY concurrent full-text/spatial
        // mutator retires — a sibling writer's still-uncommitted mutation is never prematurely exposed.
        // A no-op for a non-mutating transaction.
        self.index
            .borrow_mut()
            .commit_ft_spatial_marker(txn, commit_ts);

        // 3) Publish the outcome: record the commit in the SSI tracker (kept for later conflict
        //    resolution until GC) and close the transaction.
        self.ssi.borrow_mut().record_commit(txn, commit_ts);
        // Drop this txn's bitmap abort-repair tracking (`rmp` #453, F-IDX-3): on commit the eagerly
        // maintained bitmap already reflects the now-committed writes, so there is nothing to re-derive
        // — only the bookkeeping is freed (a no-op unless a bitmap index was touched).
        self.index.borrow_mut().forget_dirty_bitmap_nodes(txn);
        // Drop this txn's derived-index undo log too (`rmp` #992): on commit its entries describe
        // committed writes and must stay, so only the bookkeeping is freed.
        self.index.borrow_mut().forget_txn_entries(txn);
        self.with_active(|a| a.remove(&txn));
        Ok(commit_ts)
    }

    /// Commit-**PREPARE** (cross-transaction group commit, phase 1, `04 §4.2` / `rmp` #528): runs SSI
    /// validation and the FULL in-memory commit publish of `txn` (assign commit timestamp, publish the
    /// SSI outcome + full-text/spatial marker, retire the transaction) EXCEPT the WAL
    /// group-commit `fdatasync`. Every observable effect is identical to [`commit`](Self::commit); only
    /// the durability sync is deferred, so the engine can PREPARE many committers and then issue ONE
    /// [`harden_wal`](Self::harden_wal) covering the whole batch.
    ///
    /// Returns `(commit_ts, commit_lsn)` where `commit_lsn` is `Some` iff a durable `COMMIT` record was
    /// appended (a real write commit the batch `fdatasync` must cover) or `None` for the read-only fast
    /// path (`rmp` #529 — nothing appended, nothing to harden). The caller MUST
    /// [`harden_wal`](Self::harden_wal) (advancing the durable watermark past `commit_lsn`) **before**
    /// acknowledging `txn` to its client — the ack-after-fsync durability rule.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not open.
    /// - [`GraphusError::Transaction`] (retriable serialization failure) if `txn` is the SSI abort
    ///   victim — it is rolled back and its client should retry. **An aborted pivot never joins a
    ///   batch** (it appended no `COMMIT` record), so the caller answers it the error immediately.
    /// - A storage error if the store PREPARE fails.
    pub fn commit_prepare(&self, txn: TxnId) -> Result<(Timestamp, Option<Lsn>)> {
        let isolation = self
            .with_active(|a| a.get(&txn).map(|t| t.isolation))
            .ok_or_else(|| {
                GraphusError::Transaction(format!("commit of inactive txn {}", txn.0))
            })?;

        // 1) SSI validation (SERIALIZABLE only): abort a pivot on a dangerous structure (`04 §5.4`) —
        //    identical to `commit`. An aborted pivot never reaches the WAL PREPARE below.
        if isolation.runs_ssi() {
            let victim = self.ssi.borrow().detect_pivot_abort(txn);
            if let Some(victim) = victim {
                self.break_dangerous_structure(txn, victim)?;
            }
        }

        // 2) Store PREPARE: assign the commit timestamp, publish the outcome and append the `COMMIT`
        //    record WITHOUT hardening (`rmp` #528). The store is the timestamp oracle.
        // The store returns the timestamp it assigned — see `commit` above for why re-reading the
        // clock here is wrong under `D-multi-writer` (`rmp` #1056).
        let (commit_ts, commit_lsn) = self.store.borrow_mut().commit_prepare(txn)?;

        // 3) Publish the outcome — byte-identical to `commit` (the WAL harden is the only deferred step).
        self.index
            .borrow_mut()
            .commit_ft_spatial_marker(txn, commit_ts);
        // LOAD-BEARING for the pipelined group commit (`rmp` #583, F1b): `record_commit` publishes the
        // committer's timestamp into the SSI tracker HERE, at PREPARE time — *before* the WAL harden, and
        // before `pipelined_group_commit` may drain an off-thread reader's retirement between two hardened
        // batches. That retirement folds the reader's SIREAD markers and runs `detect_pivot_abort`; because
        // a prepared-but-unhardened writer is already recorded committed (and removed from `active` below),
        // the reader's rw-edge to it fires the eager committed-pivot break and correctly dooms the read-only
        // reader on a dangerous structure. If this `record_commit` were ever deferred to harden/complete
        // time (leaving prepared writers "active" in SSI), that mid-pipeline merge could MISS the structure
        // — so this ordering must not move.
        self.ssi.borrow_mut().record_commit(txn, commit_ts);
        self.index.borrow_mut().forget_dirty_bitmap_nodes(txn);
        // And this txn's derived-index undo log (`rmp` #992): its entries describe writes that are now
        // committed, so they must stay. A no-op unless an index covered something it wrote.
        self.index.borrow_mut().forget_txn_entries(txn);
        self.with_active(|a| a.remove(&txn));
        Ok((commit_ts, commit_lsn))
    }

    /// Group-commit **HARDEN** (phase 2, `04 §4.2` / `rmp` #528): `fdatasync`s the WAL, making every
    /// record appended by the [`commit_prepare`](Self::commit_prepare)s since the last harden durable in
    /// ONE sync — the whole batch of concurrent committers. Call after the last PREPARE and **before**
    /// acknowledging any committer (the ack-after-fsync rule). A no-op syscall when nothing is pending
    /// (a batch of only read-only commits).
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`04 §4.9`, fsyncgate) — the WHOLE
    /// batch fails together (none of its members are acked), which is correct.
    pub fn harden_wal(&self) {
        self.store.borrow_mut().harden_wal();
    }

    /// Group-commit **HARDEN — PREPARE half** of a *pipelined* commit (`rmp` #532): writes every
    /// [`commit_prepare`](Self::commit_prepare)d record to the WAL backing store (advancing its write
    /// frontier) and returns the deferred [`FsyncJob`](graphus_wal::FsyncJob), WITHOUT `fdatasync`ing.
    /// The engine offloads the job to a dedicated fsync thread and overlaps the sync with preparing
    /// the next batch, then calls [`complete_harden_wal`](Self::complete_harden_wal) with the job's
    /// `target_len` once the job has run — the two-phase split of [`harden_wal`](Self::harden_wal).
    ///
    /// The commit is committed-**durable** only after the job runs *and* `complete_harden_wal`
    /// returns, so the caller MUST NOT acknowledge any committer before then (ack-after-fsync). A
    /// crash in the overlap loses the un-synced batch WHOLE (torn-tail recovery truncates), which is
    /// correct precisely because no committer was acked.
    ///
    /// # Panics
    /// Panics (fsyncgate, `04 §4.9`) if writing the records to the backing store fails.
    pub fn begin_harden_wal(&self) -> graphus_wal::FsyncJob {
        self.store.borrow_mut().begin_harden_wal()
    }

    /// Group-commit **HARDEN — COMPLETE half** of a pipelined commit (`rmp` #532): advances the WAL
    /// durable watermark to `target_len` (the `FsyncJob::target_len` of the job returned by
    /// [`begin_harden_wal`](Self::begin_harden_wal)) after that job's `fdatasync` has run. Monotonic
    /// (composes with an eviction's inline hardening during the overlap). Call **before** acking any
    /// committer whose record the job covered.
    pub fn complete_harden_wal(&self, target_len: u64) {
        self.store.borrow_mut().complete_harden_wal(target_len);
    }

    /// The store's **durable-write commit-timestamp high-water** (`rmp` task #813): the largest commit
    /// timestamp of a write commit whose `COMMIT` record is `fdatasync`-durable. This is the engine's
    /// source for a **read** transaction's (and a schema DDL's) Bolt causal bookmark
    /// (`"<db>:<ts>"`): it always names an already-durable commit, never decreases, and is IDENTICAL for
    /// two reads with no write between them — unlike [`RecordStore::snapshot_ts`], which a read-only
    /// commit's `rmp` #529 phantom tick would advance. Drains any newly-hardened prepared write first, so
    /// the value is exact even between two group-commit hardens (interior mutability via the store's
    /// `RefCell`, hence `&self`).
    #[must_use]
    pub fn durable_write_commit_ts(&self) -> Timestamp {
        self.store.borrow_mut().durable_write_commit_ts()
    }

    /// Runs the redo-bounding auto-checkpoint if enough WAL has accumulated (`rmp` storage audit F3),
    /// a no-op otherwise. The engine's group-commit path calls this **once per drained batch**, after
    /// its committers are acknowledged (their commits are already durable via
    /// [`harden_wal`](Self::harden_wal); a checkpoint only bounds later recovery redo).
    ///
    /// # Errors
    /// Returns a storage error if flushing the dirty pages or syncing the device fails.
    pub fn checkpoint_if_due(&self) -> Result<()> {
        self.store.borrow_mut().checkpoint_if_due()
    }

    /// The **oldest** read snapshot timestamp among the coordinator's open transactions — the
    /// low-water mark of what any live reader can still observe — or `None` when no transaction is
    /// open (`rmp` #337 Slice 2, the #220 premature-reclamation class).
    ///
    /// Every open transaction (read-only readers **included**: a `MATCH` that never writes still holds
    /// a snapshot at its begin timestamp and can read any version live at that timestamp) contributes
    /// its `snapshot.ts`; the minimum is the oldest version any of them could still need. This is the
    /// **only** safe upper bound for a [`RecordStore::gc`] watermark while readers are open: `gc`
    /// physically frees a slot whose `xmax` committed `<= watermark` and returns it to the free list
    /// for reuse, so a watermark above this low-water would let `gc` reclaim — and a later writer
    /// reuse — a slot that an older still-open reader's snapshot must still see, which is exactly the
    /// freed/reused-slot read (a lost-version / wrong-row ACID violation) the #220 class describes.
    ///
    /// A read-only transaction does not advance the commit timestamp, so under a steady stream of
    /// short readers this tracks the store's high-water; a single long-running reader pins it back to
    /// that reader's begin timestamp, deliberately holding reclamation of everything it might read.
    #[must_use]
    pub fn oldest_active_snapshot(&self) -> Option<Timestamp> {
        // `rmp` #973: the reclamation floor every GC watermark derives from. A transaction that
        // begins (or ends) either side of this read moves the floor, so which interleaving reaches it
        // decides what GC is allowed to reclaim — exactly the kind of ordering a seed must be able to
        // replay.
        graphus_core::sched::yield_at(
            graphus_core::sched::YieldSite::SnapshotOldestActive,
            graphus_core::sched::ResourceId::NONE,
        );
        self.with_active(|a| a.values().map(|t| t.snapshot.ts).min())
    }

    /// The [`TxnId`]s of open transactions whose lifetime (`now_nanos − begin`) is **at least**
    /// `max_age_nanos`, where `now_nanos` and each transaction's begin reading both come from the
    /// engine's **monotonic** clock (`rmp` #395). The result is sorted by id (deterministic). This is
    /// the detection half of the **maximum-transaction-age** guard (`rmp` #477).
    ///
    /// Only transactions opened through [`begin_at`](Self::begin_at) (the server's open path) are
    /// age-tracked; one opened through the clock-agnostic [`begin`](Self::begin) (the TCK / unit tests)
    /// is never reported. `max_age_nanos == 0` **disables** the cap and returns empty.
    ///
    /// ## Why this exists
    ///
    /// A long-running reader — a single sustained `BEGIN`, or one a client keeps *active* by
    /// periodically touching it so the inactivity sweep never fires — pins
    /// [`oldest_active_snapshot`](Self::oldest_active_snapshot), the GC low-water mark, indefinitely. No
    /// dead version committed after its snapshot can then be reclaimed, so the store and RAM grow
    /// without bound with other transactions' write rate (the classic "idle-in-transaction blocks
    /// vacuum" denial of service). The age cap bounds a transaction's *total lifetime*, complementing
    /// the inactivity timeout (which a periodically-touched holder evades).
    ///
    /// The cap is **wall-clock-driven**, hence non-deterministic, so the detection is kept here (pure,
    /// clock-agnostic — the caller supplies `now_nanos`) while only the production engine drives it; the
    /// deterministic `LocalEngine` / DST path never calls it, preserving replay determinism.
    ///
    /// ## Contract for the caller (the engine)
    ///
    /// Aborting a reported transaction is the caller's job and **must** be a clean
    /// [`rollback`](Self::rollback): that removes it from the active set so
    /// [`oldest_active_snapshot`](Self::oldest_active_snapshot) advances and a subsequent
    /// [`gc`](Self::gc) reclaims what it had pinned, while its SSI / lock / store state is discarded
    /// atomically (no partial commit). Its next use then surfaces a clean retriable
    /// [`GraphusError::Transaction`]. The engine additionally excludes auto-commit statements (transient
    /// single-statement units, bounded by the per-statement timeout) and the one statement currently
    /// executing inline, so a reap never races a live read.
    #[must_use]
    pub fn aged_transactions(&self, now_nanos: u64, max_age_nanos: u64) -> Vec<TxnId> {
        if max_age_nanos == 0 {
            return Vec::new();
        }
        let mut aged: Vec<TxnId> = self
            .with_active(|active| {
                active
                    .iter()
                    .filter_map(|(id, a)| {
                        let begin = a.begin_nanos?;
                        (now_nanos.saturating_sub(begin) >= max_age_nanos).then_some(*id)
                    })
                    .collect::<Vec<_>>()
            })
            .into_iter()
            .collect();
        aged.sort_unstable();
        aged
    }

    /// The safe GC watermark **right now**: the oldest open reader's snapshot
    /// ([`oldest_active_snapshot`](Self::oldest_active_snapshot)), or — when no transaction is open —
    /// the store's current snapshot high-water ([`RecordStore::snapshot_ts`]), at which everything
    /// committed is reclaimable because no live reader can observe a reclaimed version (`rmp` #337
    /// Slice 2). This is the watermark every GC invocation path that could run with a live reader MUST
    /// use; [`gc`](Self::gc) computes it for the caller so a future GC trigger (`rmp` #305) cannot
    /// reintroduce the premature-reclamation bug by passing `snapshot_ts()` directly.
    #[must_use]
    pub fn gc_watermark(&self) -> Timestamp {
        self.oldest_active_snapshot()
            .unwrap_or_else(|| self.store.borrow().snapshot_ts())
    }

    /// Runs one MVCC garbage-collection pass over the store at the **reader-safe watermark**
    /// ([`gc_watermark`](Self::gc_watermark)), in its own internal transaction, and returns what it
    /// reclaimed/froze (`rmp` #337 Slice 2, staging for the #305 GC trigger).
    ///
    /// This is the *correct-by-construction* GC entry point: it derives the watermark from the open
    /// reader set rather than trusting the caller, so it physically reclaims **only** versions no
    /// still-open reader can observe (the #220 premature-reclamation guard). There is no production
    /// trigger calling it yet (`rmp` #305 owns scheduling); it stages the accounting so that when a
    /// trigger lands it calls this — never `store.gc(snapshot_ts())` — and the regression scenario in
    /// `graphus-dst` proves the watermark has teeth.
    ///
    /// The GC pass is itself a transaction the coordinator opens and commits here (its frozen headers
    /// become durable on commit, exactly as [`RecordStore::gc`] documents); it does not run SSI
    /// validation (a system maintenance txn touches only reclaimable tombstones, no user predicate).
    /// It must not run while a statement seam holds the store borrow — the same discipline
    /// [`with_store_mut`](Self::with_store_mut) requires.
    ///
    /// # Errors
    /// Propagates a storage error from the GC pass or its commit.
    pub fn gc(&self) -> Result<GcPassReport> {
        self.gc_scoped(false)
    }

    /// A **freeze-only** GC pass (`rmp` #590): drives [`RecordStore::gc_freeze_only`] instead of
    /// [`RecordStore::gc`], so it advances the WAL reclaim floor (the incremental freeze sweep) without
    /// paying the `O(store)` reclamation sweeps. Used only by the mid-bulk-load maintenance cadence — see
    /// [`checkpoint_reader_safe_freeze_only`](Self::checkpoint_reader_safe_freeze_only).
    fn gc_scoped(&self, freeze_only: bool) -> Result<GcPassReport> {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        let watermark = self.gc_watermark();
        self.next_txn_id.fetch_add(1, Ordering::Relaxed);
        let gc_txn = TxnId(self.next_txn_id.load(Ordering::Relaxed));
        // `rmp` #992: tell the store what the derived indexes cover, so the pass reports the entries
        // the versions it destroys leave behind. Re-derived on every pass rather than kept in step
        // incrementally — a declaration that can drift is a declaration that will.
        self.declare_index_interest();
        // ### The longest store borrow in the coordinator, and why it is sound (`rmp` #1010)
        //
        // This one guard spans `begin` → `gc`/`gc_freeze_only` → (`rollback` |`commit`), i.e. an
        // `O(store)` sweep **and** a durability barrier (`fdatasync`). It is the widest hold of the six
        // this task audited, so it is the one worth stating explicitly.
        //
        // **Why no re-entrancy is possible.** Everything called inside is an inherent method on
        // `RecordStore`, reached through the guard. `RecordStore` holds no handle to this coordinator
        // and therefore has no path back to `self.store` — it cannot re-enter the cell no matter how
        // deep the sweep goes. The buffer-pool eviction a sweep may trigger takes the *pool's* locks
        // and, through the WAL rule, `graphus_storage::wal_rule::SharedWal` — a different `Arc<Mutex>`
        // over a different value, whose own lock-ordering discipline is documented there. Nothing on
        // that path re-acquires this cell. `gc_watermark()` above borrows the store too, but as a
        // temporary in a preceding statement, so it is released before this guard is taken.
        //
        // **Why it is not shortened.** The three calls are one atomic maintenance transaction: the pass
        // must commit (or roll back) on the very store image it swept. Releasing the guard between them
        // would, the moment a second writer exists, let another transaction interleave between the
        // sweep and its commit — trading a documented hold for a correctness hole.
        //
        // **What it costs, and when that starts to matter.** Holding a lock across an `fdatasync` is
        // exactly the convoy shape `graphus_core::latch` exists to prevent elsewhere. It is free today
        // (one thread, so the lock is uncontended) and stays free while the engine is single-writer.
        // The moment layers 3-7 admit a second writer, this hold becomes a serialisation point and must
        // be revisited — the fix will be the same one `rmp` #974/#993 applied to the pool: hoist the
        // barrier out of the locked region, not shorten the transaction.
        let store = self.store.borrow_mut();
        store.begin(gc_txn);
        let gc_result = if freeze_only {
            store.gc_freeze_only(gc_txn, watermark)
        } else {
            store.gc(gc_txn, watermark)
        };
        let report = match gc_result {
            Ok(report) => report,
            Err(e) => {
                // Best-effort undo of the partial pass so the store stays consistent for the caller.
                let _ = store.rollback(gc_txn);
                // `rmp` #992: drain and DISCARD. A rolled-back pass destroyed no version, so it
                // warrants no removal — and draining unconditionally is what stops the queue from
                // being attributed to the next pass.
                drop(store.take_dead_index_keys());
                return Err(e);
            }
        };
        if let Err(e) = store.commit(gc_txn) {
            // `rmp` #992: same disposal as the failed-pass arm above, and for the same reason. A pass
            // whose commit failed made no reclamation durable, so it warrants no removal — and leaving
            // the queue standing would offer it to whichever pass drains next.
            drop(store.take_dead_index_keys());
            return Err(e);
        }
        // `rmp` #992: only a COMMITTED pass hands its dead keys over — its reclamation is durable, so
        // the versions really are gone. Taken while the borrow is still held; acted on after it is
        // released, because the collection reads the store and then writes the index, and this engine
        // never holds those two at once (`record_graph::reindex_node`'s two-phase discipline).
        let dead = store.take_dead_index_keys();
        let collected = self.collect_dead_index_keys(gc_txn, &dead);
        let totals = &mut builds.index_collection_totals;
        totals.entries_removed += collected.entries_removed as u64;
        totals.entities_purged += collected.entities_purged as u64;
        totals.keys_retained += collected.keys_retained as u64;
        totals.abandonments += u64::from(collected.abandoned);
        Ok(report)
    }

    /// Declares to the store what the derived indexes cover, for the GC pass about to run
    /// (`rmp` #992). See [`graphus_storage::IndexInterest`].
    ///
    /// The property half is a real filter — it is what keeps a dead value's (possibly overflow-heap-
    /// reading) decode from happening for a property no index covers.
    ///
    /// The label half is an unconditional `true` because the structure it gates is unconditional: this
    /// engine always has a label index, covering every label there is.
    ///
    /// The entity half is **not** unconditional. A [`graphus_storage::DeadIndexKey::Entity`] can only
    /// act on the entity-keyed kinds (full-text, spatial, text, vector, bitmap), so on a database with
    /// none of them every reclaimed entity would spend part of the GC's bounded report budget on a key
    /// that does nothing — crowding out exactly the property keys `rmp` #992 exists to collect.
    fn declare_index_interest(&self) {
        let interest = {
            let index = self.index.borrow();
            let mut prop_keys: HashSet<u32> = HashSet::new();
            for (_, prop_key) in index.registered_node_properties() {
                prop_keys.insert(prop_key);
            }
            for (_, prop_key) in index.registered_rel_properties() {
                prop_keys.insert(prop_key);
            }
            IndexInterest::new(prop_keys, true, index.has_any_entity_keyed_index())
        };
        self.store.borrow_mut().set_index_interest(interest);
    }

    /// Applies one GC pass's [`DeadIndexKey`]s to the derived indexes (`rmp` #992, AC2), in two phases
    /// that never overlap their borrows: **read the witness off the store, then act on the index.**
    ///
    /// Splitting it is not stylistic. The evidence is a superset-polarity store read
    /// ([`DeadKeyEvidence`]) and the action is a tree mutation, so doing them in one pass would hold
    /// the store and the index at the same time — the two-cell hold this engine deliberately does not
    /// take anywhere on the write path.
    ///
    /// # The split is what CREATES the window, and what it is guarded by (`rmp` #992, slice 3)
    ///
    /// An earlier draft of this comment sold the split as *preparation* for the multi-writer layers.
    /// That was exactly backwards and is worth stating plainly, because the sprint this task belongs
    /// to exists to admit a second writer: reading the witness and acting on it under two separate
    /// holds is a **time-of-check to time-of-use** window, and it is the one place in this mechanism
    /// where the safe error direction flips. Concretely, with a concurrent writer:
    ///
    /// * the witness reads `in_use == false` for slot `X`; the writer allocates `X`, creates a node
    ///   and indexes it; [`IndexSet::collect_dead_keys`] then purges the **new** node's entity-keyed
    ///   postings — and those kinds are candidate-only, so a missing posting is a lost row;
    /// * the witness reads no `30` for `n.age`; the writer sets `n.age = 30` and commits; the removal
    ///   deletes the entry its committed version warrants.
    ///
    /// Today neither is reachable — the engine is one writer thread (`shared_cell`'s module note), so
    /// nothing runs between the two phases. Rather than leave that as an unwritten assumption for the
    /// layer that breaks it, two O(1) fail-closed checks stand in the gap, and **what each one
    /// actually covers is stated exactly**, because a guard credited with more reach than it has is
    /// worse than no guard:
    ///
    /// 1. the index is asked whether any transaction **other than** this pass has entries in flight
    ///    ([`IndexSet::has_other_index_writer_in_flight`]), evaluated under the very hold that then
    ///    performs the removals. This covers the **uncommitted** writer whose entry a dead key names,
    ///    for the whole duration of the removals;
    /// 2. the store's commit clock is compared between reading the witness and removing — and the
    ///    second read happens **under the index's hold**, not before the store's was released
    ///    (`rmp` #1022). This covers the writer that **commits** in between.
    ///
    /// Either one abandons the whole collection, keeping every entry — always safe (a retained entry
    /// is a false positive the seek's re-check drops), free under one writer, and visible via
    /// [`DeadKeyCollection::abandoned`].
    ///
    /// # Why the two together are exhaustive (`rmp` #1022)
    ///
    /// For a removal to delete an entry some other transaction's committed version warrants, that
    /// transaction must have done two things: **advanced the commit clock**, and **published its
    /// entries under the index's hold**. Check 2 is read while this pass holds the index, so:
    ///
    /// * if the writer advanced the clock at any point since the witness, the clock differs and the
    ///   batch is abandoned;
    /// * if it has not advanced the clock, it has not committed, so its entries are in flight and
    ///   check 1 sees them;
    /// * and it cannot publish anything while we hold the index, so no third case appears mid-removal.
    ///
    /// Slice 3 read the clock while the store was still held, which left the interval between
    /// releasing the store and acquiring the index uncovered — a writer committing in exactly that gap
    /// had already drained its in-flight entries, so check 1 saw nothing and its freshly-committed
    /// entry was removed. Those are candidate-only index kinds, so a missing posting is a **lost row**
    /// that no re-check resurrects. Moving one read across one hold boundary is the whole fix; it
    /// needs no new latch order, because the clock is read lock-free
    /// ([`RecordStore::commit_clock`]) rather than by taking the store's hold inside the index's.
    fn collect_dead_index_keys(&self, gc_txn: TxnId, keys: &[DeadIndexKey]) -> DeadKeyCollection {
        if keys.is_empty() {
            return DeadKeyCollection::default();
        }
        let covered: HashSet<u32> = {
            let index = self.index.borrow();
            index
                .registered_node_properties()
                .into_iter()
                .chain(index.registered_rel_properties())
                .map(|(_, prop_key)| prop_key)
                .collect()
        };
        let mut out = DeadKeyCollection::default();
        // In batches, because the witness is the one unbounded allocation in this path: a batched
        // `DETACH DELETE` reclaims entities by the million and each one contributes an entry holding
        // two `Vec`s and its DECODED values. Deciding a slice at a time bounds the live witness to the
        // batch rather than to the pass, at the cost of re-reading an entity whose keys straddle two
        // batches — a read, never a wrong answer. The keys arrive grouped by entity (the GC emits an
        // entity's whole chain together), so straddling is the exception.
        for batch in keys.chunks(DEAD_KEY_EVIDENCE_BATCH) {
            let (evidence, ts_before, clock) = {
                let store = self.store.borrow();
                let before = store.snapshot_ts();
                let evidence = Self::read_dead_key_evidence(store, batch, &covered);
                // The clock handle, taken while the store is held; read again below WITHOUT it.
                (evidence, before, store.commit_clock())
            };
            // The store's hold is released; the index's is not yet taken. This is the interval the
            // defect lived in — see `BETWEEN_WITNESS_AND_REMOVAL`.
            #[cfg(test)]
            between_witness_and_removal();
            let mut index = self.index.borrow_mut();
            // `rmp` #1022: the second read happens HERE, under the hold that removes — not before the
            // store's hold was released. That is the whole fix, and it is one line's worth of ordering.
            //
            // Why it closes the window. A writer that makes an entry committed must do two things:
            // advance this clock, and publish its index entries under the index's hold. We are holding
            // the index, so no writer can complete the second while we remove; and if any writer
            // completed the first since the witness was read, the clock differs and we abandon. So a
            // commit either happened entirely before the witness — in which case the witness saw it —
            // or it cannot become visible in the index before we are done. The previous ordering read
            // the clock while the store was still held, leaving the interval between releasing the
            // store and acquiring the index uncovered: a writer that committed in exactly that gap had
            // already drained its in-flight entries, so check 2 below saw nothing, and its
            // freshly-committed entry was removed. That is the committed-row loss this task closes.
            //
            // Read without the store's hold, deliberately: taking it here would hold index AND store
            // at once, imposing a latch order on the engine's two hottest cells and convoying every
            // writer behind a witness read that fetches pages. See `RecordStore::commit_clock`.
            let ts_after = Timestamp(clock.load(std::sync::atomic::Ordering::Acquire));
            if ts_before != ts_after || index.has_other_index_writer_in_flight(gc_txn) {
                out.abandoned = true;
                out.keys_retained += batch.len();
                continue;
            }
            let batch_out = index.collect_dead_keys(gc_txn, batch, &evidence);
            out.entries_removed += batch_out.entries_removed;
            out.entities_purged += batch_out.entities_purged;
            out.keys_retained += batch_out.keys_retained;
        }
        out
    }

    /// Reads the superset-polarity witness for every entity `keys` names, once per entity
    /// (`rmp` #992).
    ///
    /// One read per entity, not per key: a pass that rewrote the same property a thousand times emits
    /// a thousand keys for one node, and they are all decided against the same store image.
    ///
    /// An entity whose read faults is simply **absent** from the map, which
    /// [`IndexSet::collect_dead_keys`] treats as "cannot prove it dead" and retains. A read fault must
    /// never turn a maintenance pass into a removal decision.
    ///
    /// # It filters BEFORE it decodes, like the emission side
    ///
    /// The scan is the **undecoded** `superset_scan_{node,rel}_properties`, and only candidates whose
    /// key some index covers are then decoded. Decoding walks the overflow heap, so the decoded twin
    /// (`superset_scan_*_property_values`, which decodes every candidate and lets the caller discard
    /// the uncovered ones) charges a full heap walk per unindexed property of every entity a dead key
    /// names — a 1 MB `description` on a node whose `age` was rewritten, read and allocated for
    /// nothing. Filtering only the *retained* witness bounds the memory but not that transient cost;
    /// `RecordStore::note_dead_index_keys_of_reclaim` filters first for exactly this reason, and the
    /// two sides of the mechanism must not disagree about it.
    fn read_dead_key_evidence(
        store: &RecordStore<D, S>,
        keys: &[DeadIndexKey],
        covered: &HashSet<u32>,
    ) -> HashMap<(StoreKind, u64), DeadKeyEvidence> {
        let mut out: HashMap<(StoreKind, u64), DeadKeyEvidence> = HashMap::new();
        // The covered candidates of one entity's superset scan, decoded and nothing else. `None` if
        // ANY of them failed to decode, and that is the whole point of returning an `Option`: a
        // witness with a value missing is not a smaller witness, it is a WRONG one — it says "no
        // version holds this key" about a version that does, which is the one error that removes a
        // live entry. A partial witness is therefore discarded exactly like an absent one.
        let covered_values = |chain: &graphus_storage::SupersetProperties| {
            let wanted: Vec<(u32, u8, u64)> = chain
                .candidates()
                .filter(|c| covered.contains(&c.key))
                .map(|c| (c.key, c.type_tag, c.value_inline))
                .collect();
            let mut decoded = Vec::with_capacity(wanted.len());
            for (key, type_tag, value_inline) in wanted {
                let value = store.decode_property_value(type_tag, value_inline).ok()?;
                decoded.push((key, value));
            }
            Some(decoded)
        };
        for key in keys {
            let (kind, entity) = match key {
                DeadIndexKey::Property { kind, entity, .. }
                | DeadIndexKey::Entity { kind, entity } => (*kind, *entity),
                DeadIndexKey::Label { node, .. } => (StoreKind::Node, *node),
            };
            if out.contains_key(&(kind, entity)) {
                continue;
            }
            let evidence = match kind {
                StoreKind::Node => {
                    let Ok(node) = store.node(entity) else {
                        continue;
                    };
                    let Ok(chain) = store.superset_scan_node_properties(entity) else {
                        continue;
                    };
                    let Some(property_versions) = covered_values(&chain) else {
                        continue;
                    };
                    let Ok(labels) = store.node_label_superset(entity) else {
                        continue;
                    };
                    DeadKeyEvidence {
                        property_versions,
                        labels,
                        in_use: node.mvcc.in_use(),
                    }
                }
                StoreKind::Rel => {
                    let Ok(rel) = store.rel(entity) else { continue };
                    let Ok(chain) = store.superset_scan_rel_properties(entity) else {
                        continue;
                    };
                    let Some(property_versions) = covered_values(&chain) else {
                        continue;
                    };
                    DeadKeyEvidence {
                        property_versions,
                        labels: Vec::new(),
                        in_use: rel.mvcc.in_use(),
                    }
                }
                // No other store kind owns a derived-index entry.
                _ => continue,
            };
            out.insert((kind, entity), evidence);
        }
        out
    }

    /// Drives a full **maintenance checkpoint** (`rmp` #305): a reader-safe GC pass followed by a
    /// sharp store checkpoint, so storage actually reclaims RAM (the in-memory WAL tail), disk (the
    /// sealed WAL segments below the floor), and version slots — the three resource leaks that had no
    /// production trigger (`rmp` #305 / #313 / #315).
    ///
    /// The order is load-bearing:
    ///
    /// 1. **[`gc`](Self::gc)** reclaims dead versions *and* runs the freeze sweep that settles each
    ///    committed in-flight MVCC stamp to its durable `Committed(ts)` form. Freezing is what lets
    ///    [`RecordStore`] drop a writer from its `unfrozen_commit_lsn` map — i.e. it **lowers the WAL
    ///    reclaim floor**. Without this pass first, the floor stays pinned at the oldest unfrozen
    ///    commit record and a checkpoint can free almost nothing.
    /// 2. **[`RecordStore::checkpoint`]** then flushes every dirty page home (enforcing WAL-before-data
    ///    per page), writes the clean checkpoint marker, and physically reclaims the WAL prefix below
    ///    the now-lowered floor.
    /// 3. **[`SsiTracker::prune_committed`]** finally reclaims the in-memory SSI conflict records of
    ///    committed transactions no live transaction can still conflict with (`rmp` #552). The server
    ///    engine drives every transaction through this coordinator, whose `SsiTracker` was otherwise
    ///    never pruned (its only prior caller was `TxnManager::prune`, which the server never uses), so
    ///    every committed write **and** every committed auto-commit read (`rmp` #545) accumulated a
    ///    permanent `txns`/reverse-index entry — an unbounded RAM leak and an O(N)-per-commit
    ///    `detect_pivot_abort` scan. Pruning here bounds the tracker to live-plus-recently-committed on
    ///    the same maintenance cadence as every other reclaimed resource.
    ///
    /// Durability is preserved throughout: the GC pass commits its frozen headers before the
    /// checkpoint reads the floor, the checkpoint flush makes everything prior durable on its data
    /// page before the WAL prefix is freed, and the reclaim floor still clamps to the oldest active
    /// transaction's first record (loser undo) and the oldest unfrozen commit record — so ARIES
    /// recovery over the reclaimed log is unaffected. Must run between commands on the engine thread,
    /// never while a statement seam holds the store borrow (same discipline as
    /// [`with_store_mut`](Self::with_store_mut)).
    ///
    /// # Errors
    /// Propagates a storage error from the GC pass, its commit, or the checkpoint flush/reclaim.
    /// **`rmp` #588 (sprint-52 B1).** Brackets a maintenance GC pass with the reuse barrier so the
    /// slots it frees are shadow-held from physical reuse while an off-thread reader that predates the
    /// pass may still be walking a chain through them. The engine passes `Some(next_ticket)` around a
    /// [`checkpoint`](Self::checkpoint) and `None` after; forwards to
    /// [`RecordStore::set_reuse_barrier`]. See [`release_reusable_slots`](Self::release_reusable_slots).
    pub fn set_reuse_barrier(&self, barrier: Option<u64>) {
        // `&self` since `rmp` #1012: the barrier lives inside each store's own allocation latch, so
        // arming it no longer needs exclusive access to the whole `RecordStore`.
        self.store.borrow().set_reuse_barrier(barrier);
    }

    /// **`rmp` #588.** Lifts the reuse hold on every GC-freed slot whose barrier the oldest open
    /// transaction's ticket has now reached (`barrier <= oldest_open_ticket`); `u64::MAX` (no open
    /// transaction) releases everything. The engine calls this after each maintenance pass and as
    /// readers retire, so a freed slot becomes reusable exactly when no predating reader remains — no
    /// space leak, no premature reuse. Forwards to [`RecordStore::release_held`].
    pub fn release_reusable_slots(&self, oldest_open_ticket: u64) {
        // `&self` since `rmp` #1012 — see `set_reuse_barrier` above.
        self.store.borrow().release_held(oldest_open_ticket);
    }

    /// **`rmp` #992** (observability): how many entries the value-keyed derived indexes hold in total
    /// — the label index, the node- and relationship-property indexes, and the composite indexes.
    ///
    /// These structures are in-memory, so this is the direct measure of the RAM they cost (the `rmp`
    /// #305/#313 resource class), and it is the number the `rmp` #992 collection keeps **flat** under a
    /// rewrite churn instead of letting it grow with the version count. Published by the server's
    /// maintenance cadence alongside the GC report; `O(entries)`, so never on a query path. See
    /// [`IndexSet::derived_entry_count`].
    #[must_use]
    pub fn derived_index_entries(&self) -> usize {
        self.index.borrow_mut().derived_entry_count()
    }

    /// **`rmp` #992** (observability): what every GC-driven index collection has done over this
    /// coordinator's life. See
    /// [`index_collection_totals`](Self#structfield.index_collection_totals) for how to read it —
    /// in particular why the pass report's `dead_index_keys` does not answer the same question.
    #[must_use]
    pub fn index_collection_totals(&self) -> IndexCollectionTotals {
        // ONE hold for this whole operation (`rmp` #1033): a build moves between queues,
        // and two holds would let a reader see it on both or on neither.
        let mut guard = self.builds();
        // Reborrowed once: taking two disjoint fields mutably in one call needs a single
        // `DerefMut` through the guard, not one per field.
        let builds = &mut *guard;
        builds.index_collection_totals
    }

    /// **`rmp` #588** (observability): physical slots currently shadow-held from reuse (see
    /// [`RecordStore::held_slots_len`]).
    #[must_use]
    pub fn held_slots_len(&self) -> usize {
        self.store.borrow().held_slots_len()
    }

    /// **`rmp` #588 (sprint-52 B1).** A [`checkpoint`](Self::checkpoint) whose GC reclaim is **reader-
    /// safe**: it brackets the pass with the reuse barrier so a freed physical slot is shadow-held from
    /// reuse until every transaction that predates the free has retired, then lifts the hold for every
    /// slot the oldest open transaction's ticket has passed. `reuse_barrier` is `Some(next_ticket + 1)`
    /// **only when an off-thread reader is in flight** — `next_ticket` equals the newest open
    /// transaction's own ticket (`open_tx` issues it post-increment), so `+ 1` makes the barrier
    /// strictly exceed every open ticket, and [`release_held`](graphus_storage::RecordStore::release_held)
    /// (which releases a slot once `oldest_open_ticket >= barrier`) then keeps a slot held while the
    /// newest reader is still the oldest open. `None` when no off-thread reader is in flight (the
    /// inline/DST path and the no-reader fast path): freed slots are immediately reusable and
    /// `held_slots` stays empty, preserving DST determinism. `oldest_open_ticket` is the oldest open
    /// transaction's ticket (`u64::MAX` when none is open). Every production GC reclaim trigger that can
    /// run concurrently with an off-thread reader (`rmp` #336) MUST use this, never bare
    /// [`checkpoint`](Self::checkpoint).
    pub fn checkpoint_reader_safe(
        &self,
        reuse_barrier: Option<u64>,
        oldest_open_ticket: u64,
    ) -> Result<GcPassReport> {
        self.checkpoint_reader_safe_scoped(reuse_barrier, oldest_open_ticket, false)
    }

    /// **`rmp` #590.** The freeze-only counterpart of
    /// [`checkpoint_reader_safe`](Self::checkpoint_reader_safe): it drives a freeze-only GC pass
    /// ([`gc_scoped`](Self::gc_scoped)`(true)`) — advancing the WAL reclaim floor via the incremental
    /// freeze sweep — and then the same sharp store checkpoint, but **skips** the `O(store)` reclamation
    /// sweeps. This is what lets the engine tighten the mid-bulk-load maintenance cadence (bounding the
    /// retained WAL so a crash/`STOP` **before** `?end=true` cannot leave a multi-GB un-reclaimed WAL for
    /// the next `START DATABASE` to materialise into its recovery heap) **without** reintroducing the
    /// `O(N²)` mid-load maintenance cost the property sweep would otherwise incur every pass (the Mode A
    /// checkpoint sentinel tombstones a property version per batch). The (few) dead property versions the
    /// load leaves behind are reclaimed by the ordinary full cadence after the next `START DATABASE`, or by
    /// the FULL end-of-load checkpoint (`rmp` #579) at a clean `End`. Same reader-safe barrier discipline
    /// as [`checkpoint_reader_safe`](Self::checkpoint_reader_safe) (a no-op in practice, since a freeze-only
    /// pass frees no slots).
    pub fn checkpoint_reader_safe_freeze_only(
        &self,
        reuse_barrier: Option<u64>,
        oldest_open_ticket: u64,
    ) -> Result<GcPassReport> {
        self.checkpoint_reader_safe_scoped(reuse_barrier, oldest_open_ticket, true)
    }

    fn checkpoint_reader_safe_scoped(
        &self,
        reuse_barrier: Option<u64>,
        oldest_open_ticket: u64,
        freeze_only: bool,
    ) -> Result<GcPassReport> {
        self.set_reuse_barrier(reuse_barrier);
        let outcome = self.checkpoint_scoped(freeze_only);
        // Clear the barrier BEFORE releasing so a subsequent non-GC free is not held, then lift the hold
        // on every slot whose predating readers have all retired. Both run on every path (Ok or Err).
        self.set_reuse_barrier(None);
        self.release_reusable_slots(oldest_open_ticket);
        outcome
    }

    pub fn checkpoint(&self) -> Result<GcPassReport> {
        self.checkpoint_scoped(false)
    }

    /// Shared body of [`checkpoint`](Self::checkpoint) (`freeze_only == false`) and the freeze-only
    /// maintenance path (`rmp` #590): a GC pass (full or freeze-only per `freeze_only`), then the sharp
    /// store checkpoint that reclaims the WAL prefix below the now-lowered floor, then the SSI-tracker
    /// prune.
    fn checkpoint_scoped(&self, freeze_only: bool) -> Result<GcPassReport> {
        let report = self.gc_scoped(freeze_only)?;
        self.store.borrow_mut().checkpoint()?;

        // Reclaim the SSI tracker's retained committed records (`rmp` #552). The watermark is the
        // oldest active read snapshot — the oldest *begin* timestamp among open transactions, or `None`
        // when none are open — which is precisely `SsiTracker::prune_committed`'s `low_water` contract
        // (identical to the one `TxnManager::run_gc` passes). A committed transaction whose commit is
        // `<= low_water` committed before every open transaction began, so it is concurrent with no live
        // transaction: `are_concurrent` gates every rw-edge on concurrency, so no live transaction holds
        // (or can newly form) an edge to or from it, and forgetting it can never hide a dangerous
        // structure `detect_pivot_abort` would catch (the documented no-false-negative retention rule,
        // the same PostgreSQL applies to its committed-SSI summary). `gc()` above opens its maintenance
        // transaction on the *store* only (never `self.active`/`self.ssi`), so it does not perturb this
        // watermark. Serializability for live transactions is untouched: only committed records strictly
        // below the live low-water are forgotten.
        let low_water = self.oldest_active_snapshot();
        self.ssi.borrow_mut().prune_committed(low_water);

        Ok(report)
    }

    /// The current durable WAL length in bytes (the group-commit watermark). The engine's background
    /// maintenance cadence (`rmp` #305) reads this to decide when enough WAL has accumulated since the
    /// last maintenance [`checkpoint`](Self::checkpoint) to drive another one — bounding the resource
    /// drift (RAM/disk/version slots) between operator-triggered checkpoints.
    #[must_use]
    pub fn wal_durable_len(&self) -> u64 {
        self.store.borrow().with_wal(|w| w.durable_len())
    }

    /// The live store size in bytes (mapped durable device pages × [`graphus_io::PAGE_SIZE`]).
    ///
    /// The engine's adaptive maintenance cadence (`rmp` #556) reads this alongside
    /// [`wal_durable_len`](Self::wal_durable_len) to size the WAL reclaim interval proportionally to the
    /// store, so a small OLTP store is not left with a WAL tens of times its size. Backed by the cheap,
    /// non-allocating [`RecordStore::store_page_count`], so it is safe to call on every mutating command.
    #[must_use]
    pub fn store_byte_len(&self) -> u64 {
        self.store
            .borrow()
            .store_page_count()
            .saturating_mul(graphus_io::PAGE_SIZE as u64)
    }

    /// Rolls `txn` back: undoes its writes on the store, forgets its SSI markers, and frees its
    /// active-set slot.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not open, or a storage error if the undo
    /// fails.
    pub fn rollback(&self, txn: TxnId) -> Result<()> {
        if !self.with_active(|a| a.contains_key(&txn)) {
            return Err(GraphusError::Transaction(format!(
                "rollback of inactive txn {}",
                txn.0
            )));
        }
        self.abort(txn)
    }

    /// The number of currently open transactions (observability / tests).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.with_active(|a| a.len())
    }

    /// Whether the **store** still holds `txn` as an open, unresolved writer (`rmp` #955) — i.e. its
    /// mutations are still physically present and attributable to a transaction that has neither
    /// committed nor been undone.
    ///
    /// This is deliberately the *store's* answer, not this coordinator's. [`abort`](Self::abort) frees
    /// the coordinator-level footprint (SSI markers, the `active` entry) in a drop guard that
    /// fires even when the durable undo fails or panics (`rmp` #415), because a dangling rw-edge would
    /// false-abort innocent successors. The store's active-set entry is the opposite obligation: it
    /// survives a failed undo precisely so that
    /// [`uncommitted_data_writer`](RecordStore::uncommitted_data_writer) keeps the `rmp` #902
    /// constraint-DDL guard fail-CLOSED over data nothing has undone. The two are not redundant, and
    /// only this one distinguishes "the rollback did not happen" from "there was nothing to roll back".
    ///
    /// That distinction is what the engine needs: a [`rollback`](Self::rollback) of an already-resolved
    /// or unknown transaction returns `Err` too, and it is entirely benign (the idempotent
    /// double-rollback). Degrading an engine on *that* would take a healthy database out of service on
    /// a routine race.
    ///
    /// Use this, never `commit_registry().outcome(txn) == TxnOutcome::InFlight` — that arm is dead
    /// (always `false`), and mistaking it for this question has already caused two silent-data-loss
    /// defects (`rmp` #522, `rmp` #778). See [`RecordStore::is_txn_active`].
    #[must_use]
    pub fn store_txn_unresolved(&self, txn: TxnId) -> bool {
        self.store.borrow().is_txn_active(txn)
    }

    /// Test-only witness that the SSI engine still tracks `txn` (a live conflict record / dangling
    /// rw-edge). Used by the `rmp` #415 regression to assert that an abort whose durable store undo
    /// failed/panicked nonetheless freed the transaction's SSI footprint.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn ssi_tracks(&self, txn: TxnId) -> bool {
        self.ssi.borrow().tracks(txn)
    }

    /// The SSI tracker's retained-conflict-record count — the size of its `txns` table, the single
    /// unbounded-growth vector the tracker exposes (`rmp` #552 / #591 D-#1). It is the direct witness that
    /// [`checkpoint`](Self::checkpoint)'s `prune_committed` shrank the tracker after a burst of committed
    /// transactions and auto-commit reads, and the value the engine publishes as the
    /// `graphus_ssi_tracked_transactions` observability gauge so an operator can alert on a long-lived
    /// active reader pinning the GC watermark (retention is REQUIRED for serializability — this surfaces
    /// the growth, it does not change it). An O(1) map length read.
    #[must_use]
    pub fn ssi_tracked_len(&self) -> usize {
        self.ssi.borrow().tracked_len()
    }

    /// The **effective** full-text/spatial freshness marker (`rmp` tasks #467 / #756) — the timestamp an
    /// inline reader compares its MVCC snapshot against to decide the fast index path vs the always-correct
    /// scan fallback (see [`RecordStoreGraph::index_seek_text`] and friends). It is
    /// [`Timestamp(u64::MAX)`] while any full-text/spatial mutator is in flight OR the marker is
    /// **poisoned** (a rolled-back remove/replace, or a `rmp` #733 faulted rebuild), which forces every
    /// inline reader onto the scan path; otherwise it is the committed trustworthy-from timestamp. A
    /// read-only diagnostic (used by the `rmp` #756 regression tests to witness that a rolled-back pure
    /// INSERT does not poison while a rolled-back remove/replace does).
    #[must_use]
    pub fn effective_ft_spatial_marker(&self) -> Timestamp {
        self.index.borrow().effective_ft_spatial_marker()
    }

    /// Reclaims the underlying store once no transaction is open and no statement seam is live
    /// (tests / shutdown).
    ///
    /// # Panics
    /// Panics if a statement seam still shares the store (a live [`RecordStoreGraph`] from
    /// [`statement`](Self::statement) has not been dropped).
    #[must_use]
    pub fn into_store(self) -> RecordStore<D, S> {
        match self.store.into_inner() {
            Ok(store) => store,
            Err(_) => panic!("into_store requires that no statement seam still shares the store"),
        }
    }

    /// Installs the shared **drain-progress beacon** into the underlying store (`rmp` #563). The engine
    /// calls this once at startup with the same [`AtomicU64`](std::sync::atomic::AtomicU64) it exposes on
    /// its handle, so the store's long GC/flush loops heartbeat it and the server's `stop_engine` can
    /// distinguish a slow-but-progressing drain from a wedged one.
    pub fn set_drain_progress(&self, beacon: std::sync::Arc<std::sync::atomic::AtomicU64>) {
        self.store.borrow_mut().set_drain_progress(beacon);
    }

    /// Runs `f` with **mutable** access to the underlying store, without consuming the coordinator.
    ///
    /// This is the lending counterpart to [`into_store`](Self::into_store): it gives storage-level
    /// maintenance that needs `&RecordStore` (a backup capture, an explicit checkpoint) a way to
    /// run *between* commands and leave the coordinator usable afterwards.
    ///
    /// **The single-engine-thread premise this used to rest on is gone** (`rmp` #1032/#1033). The
    /// store handle is a lock-free `SharedRef` and every store method takes `&self`, so `f` gets `&`
    /// rather than `&mut`, nothing is borrowed exclusively, and a concurrent statement on another
    /// thread is not merely tolerated but expected. What remains true — and is now the store's own
    /// business rather than this seam's — is that each operation `f` performs is ordered by the
    /// store's internal latches, not by there being one caller.
    /// Runs `f` with the coordinator's open-transaction table held (`rmp` #1033).
    ///
    /// A closure rather than a guard, deliberately: this table is touched by every statement, so a
    /// guard escaping into a caller is a hold of unbounded length, and two of them on one thread are
    /// the deadlock the index-build latch had to grow a tripwire to find. `f` returns a value; the
    /// hold ends with the call.
    ///
    /// # Panics
    /// Panics if the latch is poisoned: a holder panicked mid-update, so a transaction may be
    /// half-registered — visible to one question about it and not to another.
    fn with_active<R>(&self, f: impl FnOnce(&mut HashMap<TxnId, ActiveTxn>) -> R) -> R {
        let mut guard = self
            .active
            .lock()
            .expect("INVARIANT: a poisoned active-txn latch means a half-registered transaction");
        f(&mut guard)
    }

    /// Takes the builds latch and hands back the guard, for the callers a closure cannot serve
    /// (`rmp` #1033).
    ///
    /// [`with_builds`](Self::with_builds) is the form to reach for. This one exists because most of
    /// the build machinery also touches the store, the index set or the counters, and a closure
    /// borrowing `&mut IndexBuilds` cannot also borrow `self`. Holding the guard in a local leaves the
    /// rest of `self` borrowable.
    ///
    /// # Panics
    /// Panics if the latch is poisoned — see [`with_builds`](Self::with_builds).
    fn builds(&self) -> BuildsGuard<'_> {
        // Re-entrancy tripwire (debug only), the discipline the storage latches already follow: this
        // `Mutex` is NOT re-entrant, so a second acquisition on one thread deadlocks with no
        // diagnostic whatsoever — the process simply stops. That is how this was first met: a test
        // binary sitting in `futex_wait` for ten minutes with nothing to point at. Failing loudly
        // names the offending path instead.
        #[cfg(debug_assertions)]
        BUILDS_HELD.with(|held| {
            assert!(
                !held.get(),
                "the index-build latch was taken twice on this thread (`rmp` #1033). It is not \
                 re-entrant: drop the guard before calling anything that takes it again."
            );
            held.set(true);
        });
        BuildsGuard {
            inner: self.builds.lock().expect(
                "INVARIANT: a poisoned builds latch means a build is on both queues or neither",
            ),
        }
    }

    /// Mints one fresh, coordinator-issued [`TxnId`] (`rmp` #1033).
    ///
    /// One `fetch_add`, and the single place the counter is touched. It used to be
    /// `self.next_txn_id.fetch_add(1, Ordering::Relaxed); TxnId(self.next_txn_id.load(Ordering::Relaxed))` written out at thirty-one call sites — a
    /// read-modify-write that was safe only because one thread ran them all. Under W workers two
    /// writers would read the same value and mint the SAME transaction id: two live transactions
    /// sharing an active-set entry, an undo log and a commit-registry slot, which no layer below could
    /// detect because at that level they are one transaction.
    ///
    /// `Relaxed` is sufficient and is not laxity: the only requirement is that no two calls return the
    /// same number, which `fetch_add` gives on its own. The id orders nothing by itself — a
    /// transaction's visibility comes from its snapshot and its commit timestamp, never from the
    /// ordering of its id against another's.
    fn mint_txn(&self) -> TxnId {
        TxnId(self.next_txn_id.fetch_add(1, Ordering::Relaxed) + 1)
    }

    pub fn with_store_mut<R>(&self, f: impl FnOnce(&RecordStore<D, S>) -> R) -> R {
        // `&` rather than `&mut` since `rmp` #1032: the store's whole API takes `&self`, so exclusive
        // access buys nothing and would re-serialise what layer 7b exists to unserialise. The name is
        // unchanged because the callers' intent — reach the store to MUTATE it — is unchanged.
        f(self.store.borrow_mut())
    }

    /// Mints one fresh, coordinator-issued [`TxnId`] from [`Self::next_txn_id`](Self#structfield.next_txn_id)
    /// and hands `f` mutable store access under it — **without** registering the id in
    /// [`active`](Self#structfield.active) or the SSI tracker (`rmp` #519, network
    /// bulk-import Mode A).
    ///
    /// This is the raw, transaction-agnostic sibling of [`with_store_mut`](Self::with_store_mut) (used
    /// by backup/checkpoint, which need no transaction at all): it exists for a caller that must issue
    /// its own low-level `RecordStore::begin`/`create_node`/.../`commit` sequence — exactly what
    /// `graphus_bulk`'s free ingestion functions (`ingest_node_row`/`ingest_rel_row`) do — while
    /// guaranteeing the id can never collide with one this coordinator already issued or will issue
    /// later, on this same store, via its ordinary `begin`/`begin_serializable`/etc. methods. Unlike
    /// those methods this performs **no** SSI/lock/`record_graph` bookkeeping: the caller is fully
    /// responsible for `store.begin(txn)`/`store.commit(txn)`/`store.rollback(txn)` and for ensuring no
    /// concurrent access requires conflict detection over this write (true by construction for Mode A:
    /// the target database is `Loading`, exclusive to this session, `08 §5.2`).
    ///
    /// Because the id still comes from the coordinator's own WAL-seeded counter
    /// ([`new`](Self::new) reseeds it past [`RecordStore::recovered_txn_hw`] on every open), a
    /// transaction begun+committed through this seam recovers identically to an ordinary
    /// coordinator-driven one — `graphus_wal`/`graphus_storage::recovery` redo/undo keys off each WAL
    /// record's own `TxnId` tag, never coordinator in-memory state.
    ///
    /// The store is borrowed for exactly the duration of `f`; do not call back into the coordinator
    /// from within `f` (the same `RefCell` re-entrancy hazard [`with_store_mut`](Self::with_store_mut)
    /// documents).
    ///
    /// # Panics
    /// Panics if the store is already borrowed (a live statement seam, or `f` re-enters the
    /// coordinator).
    pub fn raw_txn<R>(&self, f: impl FnOnce(TxnId, &RecordStore<D, S>) -> R) -> R {
        let txn = self.mint_txn();
        f(txn, self.store.borrow_mut())
    }

    /// Aborts `txn`: store undo, SSI forget, lock release, and removal from the open set.
    ///
    /// # Why the in-memory cleanup is unconditional (`rmp` #415)
    ///
    /// The durable store undo (`RecordStore::rollback`) is **fallible** and may even **panic** — the
    /// documented `rmp` #359 buffer-pool/`RefCell`-replay class, which `rmp` #409's `catch_recovery`
    /// now catches *and keeps the engine alive*. If we ran the undo first and bailed on its `Err`/unwind
    /// (the historical ordering), the three pure in-memory cleanups would be skipped and the
    /// transaction would **leak**: it would stay in [`active`](Self#structfield.active) forever, pinning
    /// `oldest_active_snapshot`, freezing the GC watermark (unbounded version accumulation → slow OOM),
    /// and keeping its SSI rw-edges (false-aborting innocent transactions).
    ///
    /// So the in-memory SSI / active-set state is freed **unconditionally**, whether or not the
    /// durable undo succeeds, returns `Err`, or panics. This is sound: a half-undone *durable* state is
    /// the store's concern and is reconciled by ARIES recovery on the next open; the in-memory
    /// bookkeeping carries no durability obligation and must never leak. A [`Cleanup`] drop guard runs
    /// the cleanup on every exit path (normal return, `?` early-return, or unwind). The cleanup borrows
    /// only `ssi` / `index` (distinct `RefCell`s from `store`) and `active` (a `Mutex`, not a
    /// `RefCell`), so it never conflicts with the store borrow even when that borrow is being torn down
    /// by an unwind. Each step is idempotent (`SsiTracker::forget`, `rollback_ft_spatial_marker` and
    /// `HashMap::remove` are no-ops for an absent / non-mutator txn), so a double abort cannot
    /// double-free.
    ///
    /// # Bitmap index repair (`rmp` #453, F-IDX-3)
    ///
    /// The eagerly-maintained in-memory bitmap index (`rmp` #328) reflects this transaction's
    /// uncommitted writes (a `SET n.active = false` moved `n`'s bit), so the store undo above leaves it
    /// out of sync — and because the bitmap is a *membership-exact candidate source*, a missing entry
    /// cannot be resurrected by the query-time re-check. So this txn's bitmap-dirtied node set is
    /// **drained up front** (freeing the bookkeeping unconditionally, exactly like the leak-safety of
    /// the SSI/lock state) and, *only if the durable undo succeeded*, each dirtied node is re-derived
    /// from the now-reverted store. If the undo failed/panicked the store is not cleanly reverted, so
    /// re-derivation is skipped: the bitmap may be momentarily stale, but it is in-memory, has no
    /// planner consumer yet, and is fully resynced by the next open-time rebuild — never a durability or
    /// committed-data concern.
    ///
    /// # Derived-index entry rollback (`rmp` #992)
    ///
    /// The B+-tree-backed derived indexes (label, node/relationship property, node/relationship
    /// composite) are maintained eagerly at write time too, and until now nothing undid them: a
    /// rolled-back `CREATE` left the index advertising a candidate whose write never happened. Each
    /// entry now belongs to the transaction that created it ([`IndexWriter`]), so this path removes
    /// exactly the entries `txn` created — drained up front like the bitmap set, applied only after a
    /// successful undo. Unlike the bitmap these trees are a candidate SUPERSET, so a leftover entry is
    /// merely imprecise while removing the wrong one would lose a committed row; that is why only
    /// *created* entries are logged and why a build's entries are never touched.
    fn abort(&self, txn: TxnId) -> Result<()> {
        /// Drop guard that frees the pure in-memory transaction state. Runs on normal return **and** on
        /// unwind, so a panicking store undo can never leak the SSI markers or the `active` entry.
        struct Cleanup<'a> {
            ssi: &'a SharedCell<SsiTracker>,
            index: &'a SharedCell<IndexSet>,
            /// The table itself, not a borrow of its contents: the guard runs in `Drop`, where a
            /// hold taken earlier could not be released in time (`rmp` #1033).
            active: &'a std::sync::Mutex<HashMap<TxnId, ActiveTxn>>,
            txn: TxnId,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                // All three are idempotent no-ops for an already-removed/non-mutator txn, so this is
                // safe even if the txn was somehow torn down concurrently / twice.
                self.ssi.borrow_mut().forget(self.txn);
                // Cross-snapshot freshness marker (`rmp` tasks #467, #756): retire `txn` as a
                // ROLLED-BACK full-text/spatial mutator. The store undo above (or below) does NOT roll
                // back the in-memory inverted index / grid, so a rolled-back replace/delete may leave a
                // still-committed node dropped from a posting it should occupy — a false negative the
                // query-time re-check cannot resurrect. `rollback_ft_spatial_marker` therefore pins the
                // effective marker at `u64::MAX` (every reader uses the always-correct scan path) until a
                // full store-consistent rebuild repairs the index — but ONLY when `txn` actually removed
                // or replaced a covered posting (`rmp` #756). A rolled-back pure insert (e.g. an aborted
                // `CREATE` of a new node) leaves only a re-check-filterable false positive, so it does
                // not poison and the fast path is preserved. A no-op if `txn` was not a mutator, so the
                // common (non-full-text/spatial) rollback leaves the fast path untouched.
                self.index.borrow_mut().rollback_ft_spatial_marker(self.txn);
                self.active
                    .lock()
                    .expect("INVARIANT: a poisoned active-txn latch means a half-registered transaction")
                    .remove(&self.txn);
            }
        }

        // Drain this txn's bitmap-dirtied node set BEFORE the undo (`rmp` #453, F-IDX-3): this frees the
        // per-txn bookkeeping unconditionally — like the SSI leak-safety — so even a panicking undo
        // cannot leak it. The set is complete (statement maintenance has finished by abort time) and the
        // undo never grows it, so draining now loses nothing. Re-derivation runs AFTER a successful undo.
        let dirty_bitmap_nodes = self.index.borrow_mut().take_dirty_bitmap_nodes(txn);
        // And this txn's derived-index undo log (`rmp` #992), drained here for the same reason: the
        // per-transaction bookkeeping is freed unconditionally, so a failing or panicking undo cannot
        // strand it. It is APPLIED below, and only if the durable undo succeeded.
        let index_undo = self.index.borrow_mut().take_txn_entries(txn);

        let cleanup = Cleanup {
            ssi: &self.ssi,
            index: &self.index,
            active: &self.active,
            txn,
        };
        // The durable undo runs while the guard is armed. Its borrow of `self.store` is a *different*
        // `RefCell` from the guard's `ssi`/`index`, so an `Err` (early `?` return) or a panic both leave
        // the guard free to run its cleanup on scope exit / unwind without a borrow conflict.
        let undo = self.store.borrow_mut().rollback(txn);
        drop(cleanup); // Free the in-memory state now; on `Err`/panic above this same drop runs anyway.

        // Re-derive each bitmap-dirtied node from the now-reverted store, but ONLY if the undo
        // succeeded (a failed/panicked undo leaves the store half-reverted, so a re-derive could read
        // inconsistent state — skip it; the bitmap resyncs on the next rebuild). A node's pre-image
        // value is back in the store, so this restores the bitmap to its committed membership. No-op
        // unless a bitmap index is declared (`dirty_bitmap_nodes` is then empty).
        if undo.is_ok() {
            // Remove the derived-index entries this transaction CREATED (`rmp` #992). Only entries it
            // created are in the log — a re-insert over an already-present key is never recorded — so
            // this restores the trees to exactly what they held before the transaction ran, and cannot
            // destroy an entry a committed version warrants.
            //
            // Gated on a successful undo for the same reason the bitmap re-derivation below is: a
            // failed or panicked undo leaves the store half-reverted, so the record may still carry the
            // value the entry describes. Leaving the entries then is the safe direction — a stale entry
            // is a false positive the per-candidate re-check drops, never a row lost.
            self.index.borrow_mut().undo_entries(index_undo);
            for node in dirty_bitmap_nodes {
                self.rederive_node_bitmap(node);
            }
        }
        undo
    }

    /// Re-derives node `id`'s bitmap membership from the **current** store state across every registered
    /// bitmap column (`rmp` #453, F-IDX-3): removes the node from every value-bitmap, then re-inserts it
    /// under its current store value for each covered column it still carries (via
    /// [`index_one_node_bitmap`](Self::index_one_node_bitmap), which only inserts). Used by abort to
    /// undo a rolled-back change's effect on the in-memory bitmap. Store and index are borrowed in
    /// separate, non-overlapping scopes (the file's borrow discipline). A no-op if no bitmap is declared.
    fn rederive_node_bitmap(&self, id: u64) {
        let registered = self.index.borrow().registered_bitmap();
        if registered.is_empty() {
            return;
        }
        // Clear the node from every value-bitmap first (drop the rolled-back value's bit), then
        // re-insert under the reverted store value for each column it still matches.
        self.index.borrow_mut().remove_node_from_all_bitmaps(id);
        // This is an ABORT path, not a build: it borrows `index_one_node_bitmap`, which reports an
        // unreadable node by raising the shared `rebuild_gap` flag (`rmp` task #733). Leaving that flag
        // set here would be a landmine — the next build to read it would poison itself over a fault that
        // had nothing to do with it. So the gap is consumed HERE, where it means something specific: the
        // node could not be re-derived, so the bitmap (a **membership-exact** candidate source, whose
        // holes a seek can never resurrect) no longer faithfully describes this column. Unregister the
        // affected columns — their consumers gate on registration — so every seek falls back to the exact
        // scan, and the next successful rebuild re-captures them.
        self.index.borrow_mut().clear_rebuild_gap();
        Self::index_one_node_bitmap(&self.store, &self.index, id, &registered);
        if self.index.borrow().rebuild_gap() {
            let mut index = self.index.borrow_mut();
            index.clear_rebuild_gap();
            for (label_token, prop_key) in registered {
                // RETIRE, keeping the declaration: the column stops answering seeks now, and the next
                // successful rebuild re-registers and repopulates it (`rmp` task #733, M2).
                index.disable_bitmap(label_token, prop_key);
            }
        }
    }
}

/// The coordinator-level [`Statistics`] seam (`rmp` task #82): exact catalogue counts and
/// per-indexed-property histograms over the coordinator's shared store, consumed by
/// [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats) at compile time.
///
/// # What is reported (snapshot semantics)
///
/// Each call reads the store's **current committed catalogue**: the durable grand-total and
/// per-label / per-relationship-type counts (`rmp` task #79) and the durable equi-depth property
/// histograms (`rmp` task #81). The planner treats the values as a consistent-enough snapshot for
/// one compilation; the counts are advisory cost inputs, so a materially-stale histogram (or a count
/// racing a concurrent commit) only **mis-costs** a plan — it never affects correctness, because
/// every cost-based rewrite is bag-preserving (`rmp` task #65). This deliberately mirrors the
/// catalogue-count semantics of [`RecordStoreGraph`]'s own [`Statistics`] impl: cost estimation
/// wants the aggregate shape of the data, not one transaction's MVCC view.
///
/// # Borrow discipline (and what replaced the single-engine-thread premise)
///
/// This used to be safe *because* one thread ran everything. It no longer rests on that
/// (`rmp` #1032/#1033): the seam holds a lock-free [`SharedRef`](crate::shared_cell::SharedRef)
/// clone of the store, every store method takes `&self`, and nothing here borrows exclusively — so
/// a `CoordinatorStatistics` may be held across an entire compilation, on any thread, while other
/// threads read and write the same store.
///
/// What the seam still owes, and still honours, is that any decoded value is **owned** before the
/// call returns: the statistics catalogue is copy-on-write behind the store's rank-10 catalog latch
/// (`rmp` #1015), so a borrow into it cannot outlive the call that took it. That is a property of
/// this seam's code, not of how many threads exist, which is why it survived the change.
///
/// # Error policy
///
/// This seam has **no error-capture channel** (compilation must not fail over an advisory
/// statistic), so a corrupt stored histogram degrades to the `None` "fall back" sentinel — the
/// estimator then uses its documented constants — instead of being surfaced. The per-statement
/// [`RecordStoreGraph`] seam, which *does* have a channel, captures the same error; both read
/// through the shared (crate-private) `store_statistics` helpers so the lookup semantics cannot
/// drift.
pub struct CoordinatorStatistics<D: BlockDevice, S: LogSink> {
    /// A clone of the coordinator's shared store handle (see the borrow-discipline doc above).
    store: SharedRef<RecordStore<D, S>>,
}

impl<D: BlockDevice, S: LogSink> CoordinatorStatistics<D, S> {
    /// Decodes the durable histogram for `(label, property)` via the shared reader, applying this
    /// seam's error policy: a corrupt histogram is reported as `None` (the estimator's constant
    /// fallback) because compile-time statistics are advisory and have no error channel — never a
    /// panic, never a failed compilation.
    fn decode_histogram(&self, label: &str, property: &str) -> Option<PropertyHistogram> {
        store_statistics::decode_histogram(self.store.borrow(), label, property)
            .ok()
            .flatten()
    }
}

impl<D: BlockDevice, S: LogSink> Statistics for CoordinatorStatistics<D, S> {
    fn total_nodes(&self) -> u64 {
        self.store.borrow().total_node_count()
    }

    fn nodes_with_label(&self, label: &str) -> Option<u64> {
        // Exact per-label catalogue counts (`rmp` task #79): a never-interned label is an exact
        // `Some(0)`, never the `None` "unknown" sentinel.
        Some(store_statistics::nodes_with_label(
            self.store.borrow(),
            label,
        ))
    }

    fn total_relationships(&self) -> u64 {
        self.store.borrow().total_relationship_count()
    }

    fn relationships_with_type(&self, rel_type: &str) -> Option<u64> {
        // Exact per-relationship-type catalogue counts; a never-interned type is an exact 0.
        Some(store_statistics::relationships_with_type(
            self.store.borrow(),
            rel_type,
        ))
    }

    fn rels_from_label_with_type(&self, start_label: &str, rel_type: &str) -> Option<u64> {
        // Exact `(startLabel, type)` directional counts (`rmp` task #856), or `None` when this
        // catalogue holds no directional projections at all — see `store_statistics`.
        store_statistics::rels_from_label_with_type(self.store.borrow(), start_label, rel_type)
    }

    fn rels_with_type_to_label(&self, rel_type: &str, end_label: &str) -> Option<u64> {
        store_statistics::rels_with_type_to_label(self.store.borrow(), rel_type, end_label)
    }

    fn estimate_nodes_label_property_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
    ) -> Option<f64> {
        // No histogram (or a corrupt one, per this seam's error policy) -> None (fall back); an
        // unindexable query value (Null/List/Map) likewise -> None (`store_statistics` docs).
        let hist = self.decode_histogram(label, property)?;
        store_statistics::histogram_estimate_eq(&hist, value)
    }

    fn estimate_nodes_label_property_range(
        &self,
        label: &str,
        property: &str,
        lo: Option<&Value>,
        lo_inclusive: bool,
        hi: Option<&Value>,
        hi_inclusive: bool,
    ) -> Option<f64> {
        // A *present* but unindexable bound -> None (fall back) rather than silently dropping the
        // bound; an absent bound is open on that side (`store_statistics::histogram_estimate_range`).
        let hist = self.decode_histogram(label, property)?;
        store_statistics::histogram_estimate_range(&hist, lo, lo_inclusive, hi, hi_inclusive)
    }

    fn distinct_label_property_values(&self, label: &str, property: &str) -> Option<u64> {
        Some(self.decode_histogram(label, property)?.distinct())
    }
}

#[cfg(test)]
mod abort_failure_tests {
    //! `rmp` #415 regression: an abort whose **durable store undo fails or panics** must still free
    //! the transaction's pure in-memory state (SSI markers, index rollback markers, the `active`
    //! entry), so it
    //! can never leak — pinning `oldest_active_snapshot`, freezing the GC watermark into unbounded
    //! version accumulation (slow OOM behind the `rmp` #409 503), or false-aborting innocent
    //! transactions with stale rw-edges.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use graphus_core::{GraphusError, Result, TxnId};
    use graphus_wal::{LogSink, MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;

    /// A [`LogSink`] wrapping [`MemLogSink`] whose `sync()` returns `Err` once a shared flag is armed.
    /// Because [`WalManager::harden`] treats an fsync failure as unrecoverable and **panics**
    /// (fsyncgate, `§4.9`), arming this flag turns the next `RecordStore::rollback` into the documented
    /// panic-during-undo class (`rmp` #359 / #409) — exactly the path under test. The flag is shared via
    /// `Arc<AtomicBool>` (the sink must be `Send + Sync` for the off-thread read bounds) so the test
    /// keeps a handle to arm it *after* the transaction has written, while the sink itself lives inside
    /// the coordinator's store.
    struct FaultSink {
        inner: MemLogSink,
        fail_sync: Arc<AtomicBool>,
    }

    impl LogSink for FaultSink {
        fn append(&mut self, bytes: &[u8]) {
            self.inner.append(bytes);
        }
        fn sync(&mut self) -> Result<()> {
            if self.fail_sync.load(Ordering::SeqCst) {
                return Err(GraphusError::Storage(
                    "injected rollback fdatasync failure (rmp #415)".to_owned(),
                ));
            }
            self.inner.sync()
        }
        fn begin_harden(&mut self) -> Result<graphus_wal::FsyncJob> {
            // Forward to the inner sink (mirroring `read_bounded`/`reclaimed_floor`), so `FaultSink`
            // stays a faithful `LogSink` wrapper under the pipelined-harden path (`rmp` #532). The
            // rollback fsync-failure fault this double injects fires on the inline `sync`/harden path
            // these tests drive (`RecordStore::rollback` → `WalManager::rollback` → `harden` → `sync`),
            // which is unchanged; `MemLogSink`'s default `begin_harden` hardens inline.
            self.inner.begin_harden()
        }
        fn complete_harden(&mut self, target_len: u64) {
            self.inner.complete_harden(target_len);
        }
        fn durable_len(&self) -> u64 {
            self.inner.durable_len()
        }
        fn buffered_len(&self) -> u64 {
            self.inner.buffered_len()
        }
        fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
            self.inner.read_durable(from, into)
        }
        fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
            self.inner.read_bounded(from, to, into)
        }
        fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
            self.inner.reclaim(from, up_to)
        }
        fn reclaimed_floor(&self) -> u64 {
            self.inner.reclaimed_floor()
        }
    }

    type Coord = TxnCoordinator<MemBlockDevice, FaultSink>;

    fn fresh_coord(fail_sync: Arc<AtomicBool>) -> Coord {
        let device = MemBlockDevice::new(0);
        let sink = FaultSink {
            inner: MemLogSink::new(),
            fail_sync,
        };
        let wal = WalManager::create(sink).expect("create wal");
        let store: RecordStore<MemBlockDevice, FaultSink> =
            RecordStore::create(device, wal, 64, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    /// Runs one statement under `txn`, asserting it captured no error.
    fn run_stmt(coord: &Coord, txn: TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// THE GATE. A transaction that has written (so the store undo has real work and reaches the
    /// panicking `harden`) and built an SSI / lock footprint is aborted with the store undo armed to
    /// **panic**. We assert that the panic propagates (proving the durable undo really failed) yet the
    /// pure in-memory state is freed regardless: the txn is gone from `active`, its SSI footprint is
    /// forgotten, and the GC watermark / oldest-active-snapshot can advance afterward.
    ///
    /// This must FAIL before the `rmp` #415 fix (old ordering ran the fallible undo first and skipped
    /// the three cleanups on its `Err`/unwind) and PASS after (the cleanup runs in a drop guard that
    /// fires on unwind).
    #[test]
    fn abort_failure_does_not_leak_active_txn_or_watermark() {
        let fail_sync = Arc::new(AtomicBool::new(false));
        let coord = fresh_coord(Arc::clone(&fail_sync));

        let baseline_active = coord.active_count();
        let baseline_watermark = coord.gc_watermark();

        // Open a SERIALIZABLE txn and give it a real footprint: a committed-then-read register so the
        // txn holds an SSI read marker + a write (the node create) the store must undo.
        let txn = coord.begin_serializable();
        run_stmt(&coord, txn, "CREATE (:Reg {k: 1, v: 0})");
        // A read so the SSI engine records a read marker for this txn (dangling rw-edge candidate).
        run_stmt(&coord, txn, "MATCH (n:Reg {k: 1}) RETURN n.v AS v");

        assert!(
            coord.ssi_tracks(txn),
            "precondition: the open txn must be SSI-tracked before abort"
        );
        assert_eq!(
            coord.active_count(),
            baseline_active + 1,
            "precondition: the open txn must be in the active set"
        );

        // Arm the store undo to PANIC (the `harden` fsyncgate panic), then abort. The panic is the
        // documented `rmp` #359/#409 class that `catch_recovery` catches while keeping the engine alive.
        fail_sync.store(true, Ordering::SeqCst);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // `rollback` is the public entry to `abort`; it returns `Err` only for an inactive txn, so
            // for our active txn it runs `abort`, whose store undo we have armed to panic.
            let _ = coord.rollback(txn);
        }));
        assert!(
            unwound.is_err(),
            "the armed durable undo must actually panic (proving the failure path is exercised)"
        );
        // Disarm so the post-abort assertions / drop do not re-trip the fault.
        fail_sync.store(false, Ordering::SeqCst);

        // THE ASSERTIONS: the in-memory state was freed despite the panicking undo.
        assert_eq!(
            coord.active_count(),
            baseline_active,
            "active set must return to baseline — the aborted txn must not leak (rmp #415)"
        );
        assert!(
            !coord.ssi_tracks(txn),
            "SSI footprint must be forgotten — no dangling rw-edge for the aborted txn (rmp #415)"
        );
        assert_eq!(
            coord.oldest_active_snapshot(),
            None,
            "no open reader must remain pinning the snapshot watermark"
        );
        // The GC watermark can advance again (it is no longer pinned by the leaked txn). It is at least
        // the baseline; the committed CREATE before the panic advanced the store's high-water, so it is
        // free to move forward now that no transaction is open.
        assert!(
            coord.gc_watermark() >= baseline_watermark,
            "GC watermark must be free to advance once the aborted txn is gone (rmp #415)"
        );

        // And the coordinator is still usable: a fresh txn begins, writes, commits, aborts cleanly —
        // proving neither a leaked lock nor a stale rw-edge false-aborts an innocent successor.
        let txn2 = coord.begin_serializable();
        run_stmt(&coord, txn2, "CREATE (:Reg {k: 2, v: 0})");
        coord
            .commit(txn2)
            .expect("innocent successor txn must commit");
        assert_eq!(
            coord.active_count(),
            baseline_active,
            "coordinator must be left in a clean state after the failed abort + successful successor"
        );
    }
}

#[cfg(test)]
mod max_transaction_age_tests {
    //! `rmp` #477 regression: the maximum-transaction-age guard. A long-running reader that pins the GC
    //! low-water mark ([`TxnCoordinator::oldest_active_snapshot`]) indefinitely — the classic
    //! "idle-in-transaction blocks vacuum" denial of service — is detected by
    //! [`TxnCoordinator::aged_transactions`] once its lifetime exceeds the cap and reaped by a clean
    //! [`TxnCoordinator::rollback`], so the watermark advances and dead-version retention stops growing.
    //!
    //! The clock is supplied explicitly (no wall clock), so the scenario is fully deterministic.

    use graphus_core::{GraphusError, TxnId};
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_txn::IsolationLevel;
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    /// Runs one statement under `txn`, asserting it captured no error.
    fn run_stmt(coord: &Coord, txn: TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// Nanoseconds in one millisecond — the cap is expressed in ms in the server config.
    const MS: u64 = 1_000_000;

    /// THE GATE. A long reader opened via `begin_at` pins the watermark while a churn of committed
    /// writers accumulates dead versions GC cannot reclaim. Once the reader's lifetime crosses the cap,
    /// `aged_transactions` reports it (and a younger reader is left alone); reaping it via `rollback`
    /// advances the watermark and a GC pass — which reclaimed **nothing** while pinned — now reclaims
    /// the accumulated garbage. The reaped reader's next use is a clean retriable error.
    #[test]
    fn aged_reader_is_reaped_freeing_the_gc_watermark() {
        let coord = fresh_coord();
        // The configured cap (mirrors the server's `max_transaction_age_ms`), in monotonic nanoseconds.
        let max_age_nanos = 60 * 60 * 1000 * MS; // 1 hour

        // Seed exactly one committed node at t = 0, so there is no pre-existing garbage.
        let seed = coord.begin_at(IsolationLevel::Serializable, 0);
        run_stmt(&coord, seed, "CREATE (:Reg {k: 1, v: 0})");
        coord.commit(seed).expect("seed commit");

        // A long-lived reader opens its snapshot near t = 0 and reads the register, taking SSI markers.
        let reader = coord.begin_at(IsolationLevel::Serializable, MS);
        run_stmt(&coord, reader, "MATCH (n:Reg {k: 1}) RETURN n.v AS v");
        let pinned = coord
            .oldest_active_snapshot()
            .expect("the open reader pins the GC low-water mark");

        // Churn the SAME node many times AFTER the reader's snapshot: every overwrite supersedes the
        // prior version, but each dead version committed after the reader began (xmax > the watermark),
        // so GC cannot reclaim any of it while the reader stays open.
        const CHURN: u64 = 25;
        for i in 1..=CHURN {
            let w = coord.begin_at(IsolationLevel::Serializable, MS + i);
            run_stmt(&coord, w, &format!("MATCH (n:Reg {{k: 1}}) SET n.v = {i}"));
            coord.commit(w).expect("churn writer commits cleanly");
        }
        // The reader still pins the watermark, so a GC pass reclaims (essentially) nothing.
        assert_eq!(
            coord.oldest_active_snapshot(),
            Some(pinned),
            "the long reader must still pin the watermark while it is open"
        );
        // What the churn leaves behind moved with `rmp` #967. Before it, each overwrite PREPENDED a
        // new property record and tombstoned the old one, so the garbage was dead `props.store`
        // versions and `GcPassReport::reclaimed` counted all of it. After it, the overwrite is written
        // IN PLACE and the superseded value descends onto the node's undo chain, so the garbage is
        // `undo.store` deltas — which `rmp` #966 reports in a SEPARATE field, deliberately, so that
        // `reclaimed` keeps its "live-record versions" meaning. The semantic this test protects is
        // unchanged ("reaping an over-age reader unblocks the reclamation its snapshot was pinning"),
        // so it is asserted on the total reclamation work, which is where that garbage now is.
        let pass_pinned = coord.gc().expect("gc pass while pinned");
        let reclaimed_pinned = pass_pinned.reclaimed + pass_pinned.undo_deltas_reclaimed;
        assert_eq!(
            reclaimed_pinned, 0,
            "while the reader pins the watermark, nothing the churn left behind is reclaimable \
             (records {}, undo deltas {})",
            pass_pinned.reclaimed, pass_pinned.undo_deltas_reclaimed
        );

        // Now: time has advanced one nanosecond past the cap for the reader (begin = MS), but a younger
        // reader opened just now must NOT be disturbed.
        let now = MS + max_age_nanos + 1;
        let young = coord.begin_at(IsolationLevel::Serializable, now - 1); // age 1ns << cap
        let aged = coord.aged_transactions(now, max_age_nanos);
        assert_eq!(
            aged,
            vec![reader],
            "only the over-age reader is reported — the just-opened reader is left alone"
        );

        // Reap the over-age reader with a clean rollback (the engine's contract).
        coord
            .rollback(reader)
            .expect("clean rollback of the over-age reader");

        // The watermark advanced: the young reader is now the oldest snapshot (the reaped reader is gone
        // from the active set). A GC pass — which reclaimed 0 while pinned — now reclaims the garbage the
        // reader had been holding back, proving retention stops growing.
        assert_ne!(
            coord.oldest_active_snapshot(),
            Some(pinned),
            "reaping the over-age reader must release its hold on the watermark"
        );
        let pass_after = coord.gc().expect("gc pass after reap");
        let reclaimed_after = pass_after.reclaimed + pass_after.undo_deltas_reclaimed;
        assert!(
            reclaimed_after > reclaimed_pinned && reclaimed_after > 0,
            "the advanced watermark must unblock reclamation of the pinned garbage: \
             reclaimed {reclaimed_pinned} (pinned) -> {reclaimed_after} (after reap; records {}, \
             undo deltas {})",
            pass_after.reclaimed,
            pass_after.undo_deltas_reclaimed
        );

        // The reaped reader's next use surfaces a clean retriable error — it is no longer active.
        // (`statement`'s `Ok` value is not `Debug`, so match rather than `expect_err`.)
        match coord.statement(reader) {
            Ok(_) => panic!("the reaped reader must be inactive — its next statement must error"),
            Err(GraphusError::Transaction(_)) => {}
            Err(other) => panic!(
                "a reaped over-age transaction must surface a retriable Transaction error, got: {other:?}"
            ),
        }
        assert!(
            coord.commit(reader).is_err(),
            "commit of the reaped reader errors"
        );
        assert!(
            coord.rollback(reader).is_err(),
            "rollback of the reaped reader errors (already inactive)"
        );

        // The coordinator is left clean and usable: the young reader still commits.
        coord
            .commit(young)
            .expect("the untouched young reader commits cleanly");
    }

    /// `aged_transactions` is a pure, deterministic detector: a disabled cap (`0`) reports nothing, an
    /// age-untracked transaction (opened via `begin`) is never reported, and the boundary is inclusive.
    #[test]
    fn aged_transactions_detection_rules() {
        let coord = fresh_coord();

        // Untracked (opened via the clock-agnostic `begin`): never reported, even far past any cap.
        let untracked = coord.begin(IsolationLevel::Serializable);
        // Tracked, opened at t = 1000ns.
        let tracked = coord.begin_at(IsolationLevel::Serializable, 1_000);

        // Disabled cap (0) reports nothing regardless of age.
        assert!(
            coord.aged_transactions(u64::MAX, 0).is_empty(),
            "cap 0 disables"
        );

        // Just under the cap: nothing.
        assert!(
            coord.aged_transactions(1_000 + 500, 1_000).is_empty(),
            "age 500ns < 1000ns cap — not yet aged"
        );
        // Exactly at the cap: inclusive — the tracked txn is reported, the untracked one never.
        assert_eq!(
            coord.aged_transactions(1_000 + 1_000, 1_000),
            vec![tracked],
            "age == cap is inclusive; the untracked transaction is never reported"
        );
        // `now` before begin (a monotonic clock cannot do this, but saturate rather than wrap): age 0.
        assert!(
            coord.aged_transactions(0, 1_000).is_empty(),
            "saturating age computation never reports a negative age"
        );

        let _ = untracked;
        coord.rollback(tracked).expect("rollback");
    }
}

#[cfg(test)]
mod ssi_prune_tests {
    //! `rmp` #552 regression: the maintenance checkpoint MUST prune the coordinator's `SsiTracker`.
    //!
    //! The server engine drives every transaction through this coordinator, whose `SsiTracker` was
    //! never pruned in production (its only prior caller, `TxnManager::prune`, is unused by the server).
    //! `record_commit` retains a committed transaction's record for later conflict resolution, so every
    //! committed write — and, since `rmp` #545, every committed auto-commit read demoted to Snapshot
    //! Isolation — accumulated a permanent `txns` entry: an unbounded RAM leak and an O(N)-per-commit
    //! `detect_pivot_abort` scan. `TxnCoordinator::checkpoint` now drains it at the reader-safe
    //! `oldest_active_snapshot` watermark. These tests prove the tracker GROWS without a prune and
    //! SHRINKS with one, and that pruning at the live watermark preserves serializability (it retains
    //! every record a live transaction could still conflict with).

    use graphus_core::TxnId;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    /// Runs one statement under `txn`, asserting it captured no error.
    fn run_stmt(coord: &Coord, txn: TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// THE LEAK GATE. A burst of committed writers AND committed auto-commit reads (SI-demoted, the
    /// `rmp` #545 path) each retains an SSI conflict record; with no transaction open, the maintenance
    /// checkpoint must prune every one of them. Proves the tracker GROWS to `WRITERS + READS` without a
    /// prune and SHRINKS to zero with one.
    ///
    /// Fails before the `rmp` #552 fix (`checkpoint` never pruned the tracker → `after == grown`) and
    /// passes after (`after == 0`).
    #[test]
    fn checkpoint_prunes_accumulated_committed_ssi_records() {
        let coord = fresh_coord();
        assert_eq!(
            coord.ssi_tracked_len(),
            0,
            "a fresh coordinator's SSI tracker retains nothing"
        );

        // A burst of committed writers — each `commit` retains its record (`record_commit`).
        const WRITERS: usize = 8;
        for i in 0..WRITERS {
            let w = coord.begin_serializable();
            run_stmt(&coord, w, &format!("CREATE (:N {{id: {i}}})"));
            coord.commit(w).expect("writer commits");
        }

        // A burst of committed auto-commit READS demoted to Snapshot Isolation (`rmp` #545). A clean
        // read is finalized through `commit` → `record_commit`, which retains its record too — the leak
        // this fix closes for the read-heavy workload.
        const READS: usize = 8;
        for _ in 0..READS {
            let r = coord.begin_serializable();
            coord.demote_read_to_snapshot(r);
            run_stmt(&coord, r, "MATCH (n:N) RETURN n.id AS id");
            coord.commit(r).expect("auto-commit read commits");
        }

        let grown = coord.ssi_tracked_len();
        assert_eq!(
            grown,
            WRITERS + READS,
            "every committed write AND every committed auto-commit read retains an SSI record"
        );
        assert_eq!(coord.active_count(), 0, "no transaction is open");

        // The maintenance checkpoint (`rmp` #305 / #552) prunes the tracker at `oldest_active_snapshot`
        // = None (no open transaction), so every settled committed record is forgotten.
        coord.checkpoint().expect("maintenance checkpoint");

        let after = coord.ssi_tracked_len();
        assert!(
            after < grown,
            "the checkpoint must SHRINK the SSI tracker (before {grown} -> after {after})"
        );
        assert_eq!(
            after, 0,
            "with no open transaction every committed record is settled and pruned"
        );

        // The coordinator remains fully usable after the prune.
        let w = coord.begin_serializable();
        run_stmt(&coord, w, "CREATE (:N {id: 999})");
        coord.commit(w).expect("post-prune writer commits cleanly");
    }

    /// THE WATERMARK GATE (ACID-serializability safety). Pruning must forget ONLY committed records
    /// strictly at/below the live low-water mark. With a long reader open, a checkpoint prunes the
    /// records older than the reader's snapshot but RETAINS both the reader (still in flight) and a
    /// writer that committed concurrently with it — a record that could still contribute an
    /// rw-antidependency and so must not be dropped.
    #[test]
    fn checkpoint_retains_records_a_live_reader_still_needs() {
        let coord = fresh_coord();

        // Two writers that commit BEFORE the long reader opens its snapshot.
        let pre1 = coord.begin_serializable();
        run_stmt(&coord, pre1, "CREATE (:N {id: 1})");
        coord.commit(pre1).expect("pre1 commits");
        let pre2 = coord.begin_serializable();
        run_stmt(&coord, pre2, "CREATE (:N {id: 2})");
        coord.commit(pre2).expect("pre2 commits");

        // A long-lived reader opens its snapshot and pins the GC / prune low-water mark at its begin.
        let reader = coord.begin_serializable();
        run_stmt(&coord, reader, "MATCH (n:N) RETURN n.id AS id");
        let pinned = coord
            .oldest_active_snapshot()
            .expect("the open reader pins the watermark");

        // A writer that begins AFTER the reader and commits: concurrent with the reader, its commit
        // timestamp is strictly above `pinned`, so it must survive the prune.
        let after_w = coord.begin_serializable();
        run_stmt(&coord, after_w, "CREATE (:N {id: 3})");
        coord.commit(after_w).expect("after_w commits");

        // Pre-prune: every record is present.
        assert!(coord.ssi_tracks(pre1) && coord.ssi_tracks(pre2));
        assert!(coord.ssi_tracks(reader) && coord.ssi_tracks(after_w));
        assert_eq!(
            coord.oldest_active_snapshot(),
            Some(pinned),
            "the reader still pins the low-water mark"
        );

        // Checkpoint prunes at `oldest_active_snapshot` = the reader's snapshot.
        coord
            .checkpoint()
            .expect("maintenance checkpoint with a live reader open");

        // The pre-reader writers (committed <= the watermark) are forgotten; the still-open reader and
        // the concurrent writer (committed > the watermark) are RETAINED — the serializability contract.
        assert!(
            !coord.ssi_tracks(pre1),
            "a writer committed before the live watermark is pruned"
        );
        assert!(
            !coord.ssi_tracks(pre2),
            "a writer committed at the live watermark is pruned (commit_ts <= low_water)"
        );
        assert!(
            coord.ssi_tracks(reader),
            "the still-open reader must be retained (it has no commit timestamp)"
        );
        assert!(
            coord.ssi_tracks(after_w),
            "a writer concurrent with the open reader must be retained — it could still form an rw-edge"
        );

        // The reader still commits cleanly after the prune (no serializability regression).
        coord
            .commit(reader)
            .expect("the pinned reader commits cleanly after the prune");
    }
}

#[cfg(test)]
mod index_wipe_tests {
    //! White-box regressions for the `rmp` #733 wipe/poison machinery.
    //!
    //! These live **inside** the crate on purpose. The end-to-end tests in
    //! `tests/index_fail_closed.rs` drive a faulty block device, which is the honest way to prove the
    //! engine's *behaviour* — but it cannot isolate any single guard, because the guards deliberately
    //! overlap (a wipe is covered by the epoch re-snapshot, by the degraded-promotion gate, AND by the
    //! command-path repair). An end-to-end test therefore stays green when one of them is deleted, which
    //! makes it worthless as a regression guard for that one.
    //!
    //! So each guard is pinned here against the exact adversarial state it exists for, using the
    //! coordinator's own internals. Every test below FAILS when its guard is reverted (proven, not
    //! assumed).

    use graphus_io::MemBlockDevice;
    use graphus_storage::{IndexState, Namespace, RecordStore};
    use graphus_wal::{MemLogSink, WalManager};
    use std::sync::atomic::Ordering;

    use crate::binding::{Parameters, bind_parameters};
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(coord: &Coord, src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &coord.catalog())
    }

    fn run(coord: &mut Coord, src: &str) -> Vec<crate::runtime::Row> {
        let plan = compile(coord, src);
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let rows = {
            let mut graph = coord.statement(txn).expect("statement");
            let rows = {
                let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
                cursor.collect_all().expect("collect")
            };
            assert!(!graph.has_error(), "statement captured an error");
            rows
        };
        coord.commit(txn).expect("commit");
        rows
    }

    fn seed(coord: &mut Coord, n: usize) {
        run(
            coord,
            &format!("UNWIND range(1, {n}) AS i CREATE (:Article {{slug: 'a' + toString(i)}})"),
        );
    }

    fn slug_rows(coord: &mut Coord, slug: &str) -> usize {
        run(
            coord,
            &format!("MATCH (a:Article {{slug: '{slug}'}}) RETURN id(a) AS id"),
        )
        .len()
    }

    /// **(C1, isolated.)** A wipe mid-build must make the build re-take its snapshot — not merely restart
    /// over the old one.
    ///
    /// The adversarial state is reproduced exactly: a build is half-done, a row is written **after** its
    /// snapshot (carried into the tree by `reindex_node`), then the index set is wiped. The wipe is
    /// applied directly, and the degraded flag is then cleared **without repopulating** — which is
    /// precisely the window the command-path repair leaves open when its backoff skips a probe, and the
    /// only state in which the epoch guard is the last line of defence.
    ///
    /// Resuming (or restarting over the ORIGINAL snapshot) loses the post-snapshot row for good and then
    /// promotes the index `Online` over the hole: a committed row invisible to every seek, and a
    /// uniqueness check that no longer sees the existing holder.
    #[test]
    fn a_wipe_mid_build_re_takes_the_snapshot_so_post_snapshot_rows_survive() {
        let mut coord = fresh_coord();
        seed(&mut coord, 200);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        coord.advance_index_builds(64); // half-built: the tree holds the head of the snapshot.
        assert!(coord.has_pending_index_builds());

        // A row written AFTER the build's snapshot. `reindex_node` puts it straight into the tree.
        run(&mut coord, "CREATE (:Article {slug: 'late-1'})");

        // THE WIPE, reproduced exactly as `rebuild_index` performs it: `clear()` empties every tree
        // FIRST — taking the post-snapshot row's maintenance write with it — and only then does the
        // faulting scan trigger `fail_closed()`. Calling `fail_closed()` alone would leave the trees
        // populated and the test would prove nothing (it would pass with the guard deleted).
        coord.index.borrow_mut().clear();
        coord.index.borrow_mut().fail_closed();
        // ...and the set is marked healthy WITHOUT being repopulated. This is the state a skipped repair
        // probe leaves behind, and the one in which the build's own guard is the last line of defence.
        coord.index.borrow_mut().heal();

        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_index_builds(64);
            iters += 1;
            assert!(iters < 10_000, "the build must terminate");
        }

        // The index went `Online`, so the planner routes a real seek at it...
        // Both tokens are resolved in ONE store borrow that ends before the index is consulted
        // (`rmp` #1010): two `store.borrow()` temporaries as sibling arguments would both stay live
        // to the end of the statement, which a `RefCell` permits and a `Mutex` cannot.
        let (label_token, prop_key) = {
            let store = coord.store.borrow();
            (
                store.token_id(Namespace::Label, "Article").expect("label"),
                store.token_id(Namespace::PropKey, "slug").expect("prop"),
            )
        };
        assert_eq!(
            coord
                .index
                .borrow()
                .node_property_state(label_token, prop_key),
            Some(IndexState::Online),
            "the build must complete and promote"
        );
        let probe = "MATCH (a:Article {slug: 'late-1'}) RETURN id(a) AS id";
        assert!(
            format!("{:?}", compile(&coord, probe)).contains("NodeIndexSeek"),
            "the probe must be served by an index seek — otherwise it proves nothing"
        );
        // ...and it must find the post-snapshot row. Without the re-snapshot: 0 rows.
        assert_eq!(
            slug_rows(&mut coord, "late-1"),
            1,
            "a row written after the build's snapshot must survive the wipe: the build has to \
             RE-TAKE its snapshot, not merely restart over the stale one"
        );
        assert_eq!(
            slug_rows(&mut coord, "a1"),
            1,
            "and the head of the snapshot too"
        );
    }

    /// **(B4 iii.)** A build must never promote its index while the set is degraded — and, because a
    /// degraded set may never heal, it must eventually give up rather than be re-driven forever.
    #[test]
    fn a_degraded_set_blocks_promotion_and_the_build_terminates() {
        let mut coord = fresh_coord();
        seed(&mut coord, 100);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");

        // Wipe the set and leave it degraded (no repair): the build may complete its chunks, but it must
        // not publish into a wrecked index set.
        coord.index.borrow_mut().fail_closed();

        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");

        // The engine's own drain loop. It MUST terminate: an empty chunk is not progress, so the stall
        // budget is spent rather than refilled, and the build is poisoned.
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            // Drive the build directly, so the command-path repair (which would clear `degraded` and let
            // the promotion through) cannot mask the gate under test.
            coord.advance_node_property_build(64);
            iters += 1;
            assert!(
                iters < 1_000,
                "the drain loop must TERMINATE against a degraded set — it spun {iters} times"
            );
        }
        assert_eq!(
            coord.index.borrow().node_property_state(label, prop),
            Some(IndexState::Populating),
            "a build must NEVER promote its index into a wiped index set"
        );
        assert_eq!(
            coord.index_build_poison_events(),
            1,
            "the build must be poisoned (parked + counted), not silently dropped"
        );
        assert_eq!(
            coord.poisoned_index_builds(),
            1,
            "and parked for resurrection"
        );
    }

    /// **(M1.)** A poisoned build is not a one-way door: once the store reads cleanly again it is
    /// resurrected from a fresh snapshot and completes.
    #[test]
    fn a_poisoned_build_is_resurrected_once_the_store_is_readable() {
        let mut coord = fresh_coord();
        seed(&mut coord, 100);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        coord.index.borrow_mut().fail_closed();
        // Bounded: a reverted liveness guard must FAIL this test, never hang the suite.
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_node_property_build(64);
            iters += 1;
            assert!(
                iters < 1_000,
                "the build must terminate — it spun {iters} times"
            );
        }
        assert_eq!(coord.poisoned_index_builds(), 1, "the build was poisoned");

        // The store is fine (the wipe was injected, not caused by a real fault): a repair heals the set,
        // and the parked build is then resurrected and completes.
        assert!(coord.retry_degraded_index_rebuild(), "the set repairs");
        assert!(
            coord.retry_poisoned_index_builds(),
            "the build is resurrected"
        );
        assert!(coord.has_pending_index_builds(), "and back in the queue");
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_index_builds(64);
            iters += 1;
            assert!(iters < 10_000, "the resurrected build must terminate");
        }
        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");
        assert_eq!(
            coord.index.borrow().node_property_state(label, prop),
            Some(IndexState::Online),
            "a resurrected build must finish and promote its index"
        );
        assert_eq!(coord.poisoned_index_builds(), 0);
        assert_eq!(slug_rows(&mut coord, "a1"), 1);
    }

    /// **(M2.)** A bitmap column has no durable catalog, so a fail-closed that *dropped* its declaration
    /// lost it for the life of the process. It must be RETIRED (so an empty membership-exact index never
    /// answers a seek) and brought back by the next rebuild.
    #[test]
    fn a_bitmap_declaration_survives_a_wipe() {
        let mut coord = fresh_coord();
        seed(&mut coord, 50);
        coord
            .declare_bitmap_index("Article", "slug")
            .expect("declare the bitmap column");
        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");
        assert!(coord.index.borrow().has_bitmap(label, prop));

        coord.index.borrow_mut().fail_closed();
        // Retired: it must NOT answer seeks while it is empty...
        assert!(
            !coord.index.borrow().has_bitmap(label, prop),
            "an emptied membership-exact bitmap must not stay registered"
        );
        // ...but the DECLARATION survives, so the repair rebuild restores the column.
        assert!(coord.retry_degraded_index_rebuild(), "the set repairs");
        assert!(
            coord.index.borrow().has_bitmap(label, prop),
            "a declared bitmap column must come back after the rebuild — it has no durable catalog, \
             so nothing else can restore it and it would be gone until the process restarted"
        );
    }

    /// **(B4 i / BLOCKER 1.)** The recovery promotion must ABORT on a degraded set.
    ///
    /// `TxnCoordinator::new` runs the open-time rebuild (which may fail closed) and then promotes every
    /// durably-`Populating` index to `Online` — on the premise that the rebuild has just populated it.
    /// When the rebuild failed closed that premise is false, and the promotion publishes an EMPTY index
    /// `Online`, **durably**: the planner routes a real seek at a tree with no rows in it, and
    /// `unique_conflict` — which trusts that tree as an exact candidate source — lets a `IS UNIQUE`
    /// constraint accept a duplicate. It also falsifies the in-memory state that `SHOW INDEXES` reports.
    #[test]
    fn the_recovery_promotion_aborts_on_a_degraded_index_set() {
        let mut coord = fresh_coord();
        seed(&mut coord, 50);
        // A durably-`Populating` index — exactly what an interrupted `CREATE INDEX` leaves behind.
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");
        assert!(
            coord
                .store
                .borrow()
                .node_property_indexes()
                .iter()
                .any(|&(l, p, state)| l == label && p == prop && state == IndexState::Populating),
            "the durable catalog must hold a Populating index"
        );

        // The open-time rebuild failed closed: the trees are empty and every index is demoted.
        coord.index.borrow_mut().fail_closed();

        // The recovery promotion now runs — and must refuse.
        let next = TxnCoordinator::promote_recovered_populating_indexes(
            &coord.store,
            &coord.index,
            coord.next_txn_id.load(Ordering::Relaxed),
        );
        coord.next_txn_id.store(next, Ordering::Relaxed);

        assert_eq!(
            coord.index.borrow().node_property_state(label, prop),
            Some(IndexState::Populating),
            "the recovery promotion must NOT publish an index the failed rebuild left empty"
        );
        assert!(
            coord
                .store
                .borrow()
                .node_property_indexes()
                .iter()
                .any(|&(l, p, state)| l == label && p == prop && state == IndexState::Populating),
            "and it must not flip the DURABLE state either — that would survive the restart that \
             would otherwise have repaired it"
        );
        // The index is withheld from the planner, so the query is served by the (correct) scan.
        assert!(
            !format!(
                "{:?}",
                compile(&coord, "MATCH (a:Article {slug: 'a1'}) RETURN id(a) AS id")
            )
            .contains("NodeIndexSeek"),
            "a degraded engine must not plan a seek against an empty tree"
        );
        assert_eq!(slug_rows(&mut coord, "a1"), 1, "and the row is still found");
    }

    /// **(B4 ii / BLOCKER 2.)** While degraded, `SHOW INDEXES` must never report `ONLINE` — not even for
    /// an index the recovery promotion would previously have flipped.
    #[test]
    fn show_indexes_never_reports_online_while_degraded() {
        let mut coord = fresh_coord();
        seed(&mut coord, 50);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        coord.index.borrow_mut().fail_closed();
        let next = TxnCoordinator::promote_recovered_populating_indexes(
            &coord.store,
            &coord.index,
            coord.next_txn_id.load(Ordering::Relaxed),
        );
        coord.next_txn_id.store(next, Ordering::Relaxed);

        assert!(
            coord
                .list_node_property_indexes()
                .iter()
                .all(|(_, _, _, state)| *state == IndexState::Populating),
            "a degraded engine must not report any index ONLINE: {:?}",
            coord.list_node_property_indexes()
        );
        assert!(
            !coord.label_lookup_usable(),
            "and the LOOKUP row must report the label index as unusable too"
        );
    }

    /// **(V2 — the `poison_backoff` shift clamp.)** `poison_backoff` computes `2^(attempts-1)` to widen
    /// the poisoned-build resurrection backoff. `attempts` is an unbounded `u32` (it grows once per
    /// failed resurrection over the life of a coordinator), and `1u32 << shift` is **undefined for
    /// `shift >= 32`** — in a debug build it panics `attempt to shift left with overflow`, aborting the
    /// engine thread on a merely-degraded (still-correct) store. The `(attempts - 1).min(31)` clamp is
    /// what makes it total; this pins that clamp.
    ///
    /// Reverting the clamp (`(attempts - 1)` without `.min(31)`) makes the extreme-`attempts` calls below
    /// panic, so this test FAILS — the non-vacuity proof for the clamp.
    #[test]
    fn poison_backoff_is_total_monotone_and_saturating() {
        use super::{MAX_DEGRADED_RETRY_BACKOFF, poison_backoff};

        // (a) It never panics for ANY attempts value — including every shift boundary and the extremes
        // that would overflow `1u32 << shift` without the clamp (33 ⇒ shift 32, u32::MAX ⇒ shift huge).
        for attempts in [0u32, 1, 2, 17, 18, 19, 31, 32, 33, 63, 64, 1_000, u32::MAX] {
            let b = poison_backoff(attempts);
            assert!(
                b <= MAX_DEGRADED_RETRY_BACKOFF,
                "poison_backoff({attempts}) = {b} exceeds the cap {MAX_DEGRADED_RETRY_BACKOFF}"
            );
        }

        // (b) The documented early values, then monotone non-decreasing across a full sweep, saturating
        // at the cap (never above it).
        assert_eq!(poison_backoff(0), 0, "attempts 0 is a defensive no-skip");
        assert_eq!(poison_backoff(1), 1, "the first re-poison waits 1 drain");
        assert_eq!(poison_backoff(2), 2);
        assert_eq!(poison_backoff(3), 4);
        let mut prev = 0u32;
        for attempts in 0..=64u32 {
            let b = poison_backoff(attempts);
            assert!(
                b >= prev,
                "poison_backoff must be monotone: {attempts} gave {b} < previous {prev}"
            );
            assert!(b <= MAX_DEGRADED_RETRY_BACKOFF);
            prev = b;
        }

        // (c) Once the geometric growth reaches the cap it STAYS there for every larger `attempts` — no
        // wrap, no UB, no dip. The cap is 2^18, so it is first reached at attempts = 19 (shift 18).
        assert_eq!(
            poison_backoff(19),
            MAX_DEGRADED_RETRY_BACKOFF,
            "cap first reached at 19"
        );
        for attempts in [19u32, 20, 32, 33, 64, 100, 1_000, u32::MAX] {
            assert_eq!(
                poison_backoff(attempts),
                MAX_DEGRADED_RETRY_BACKOFF,
                "poison_backoff({attempts}) must saturate at the cap, not overflow or wrap"
            );
        }
    }
}

/// `rmp` task #803 — the STRUCTURAL half of the dirty-flag fix, pinned on its own.
///
/// The end-to-end test in `graphus-cypher/tests/text_index.rs` proves the defect is gone, but it
/// cannot pin THIS layer: the fix has two redundant layers by design (each leaking build driver now
/// clears at source, AND the statement seam clears before it does any work), so the end-to-end test
/// passes with either one present. Mutation-proven: reverting only the seam scoping leaves it green.
///
/// This test removes that redundancy. It plants residue directly — the exact state a leaking build
/// leaves behind, including the `removed` bit that makes an abort POISON rather than merely
/// mis-attribute — and asserts a statement that touched no indexed property cannot inherit it. It is
/// therefore the guard for every FUTURE build driver that forgets to clear, which is the whole reason
/// the seam-level fix exists rather than trusting six one-line fixes to stay correct.
#[cfg(test)]
mod ft_spatial_statement_scope_803 {
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    fn run_stmt(coord: &Coord, txn: graphus_core::TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// Poisons the marker the supported way: a transaction REPLACES an indexed value, then aborts.
    fn poison(coord: &mut Coord) {
        let w = coord.begin_serializable();
        run_stmt(
            coord,
            w,
            "MATCH (n:Product {id: 1}) SET n.name = 'Renamed Widget'",
        );
        coord.rollback(w).expect("the replacing writer aborts");
        assert!(
            coord.ft_spatial_poisoned(),
            "precondition: a rolled-back replace of an indexed value must poison the marker"
        );
    }

    /// One drain — exactly what the engine runs after a command. `advance_index_builds` returns whether
    /// builds remain pending, and none are here, so this is a single call.
    fn drain(coord: &mut Coord) {
        while coord.advance_index_builds(usize::MAX) {}
    }

    /// `rmp` #803 — THE REPAIR MUST BE THROTTLED, and must still be LIVE.
    ///
    /// The repair is a full O(store) rebuild of every index in the database. It always SUCCEEDS, so the
    /// pre-existing `degraded_retry_backoff` — which arms only when a repair fails — never engages for
    /// it. Without a throttle of its own, a workload that keeps poisoning (an abort-heavy one on an
    /// indexed property; SSI aborts under contention are ordinary here) would buy a whole-store rebuild
    /// on EVERY command: a worse regression than the defect being fixed, which at least left queries
    /// running.
    ///
    /// Throttling is safe because the fallback is correct: while the repair waits, reads stay on the
    /// exact scan, which is exactly the pre-fix behaviour. So this test pins BOTH halves — that a
    /// repeat poisoning is throttled, and that it is nonetheless repaired soon after.
    #[test]
    fn a_repeatedly_poisoning_workload_does_not_rebuild_on_every_command() {
        let mut coord = fresh_coord();
        let seed = coord.begin_serializable();
        run_stmt(&coord, seed, "CREATE (:Product {id: 1, name: 'Widget 1'})");
        coord.commit(seed).expect("seed commits");
        coord
            .create_text_index("tx_name", "Product", "name", false)
            .expect("create text index");

        // The FIRST poisoning after a quiet period is repaired immediately — the responsiveness half.
        poison(&mut coord);
        drain(&mut coord);
        assert!(
            !coord.ft_spatial_poisoned(),
            "the first poisoning must be repaired by the very next command"
        );

        // The SECOND, back-to-back, must NOT buy another whole-store rebuild on the next command.
        poison(&mut coord);
        drain(&mut coord);
        assert!(
            coord.ft_spatial_poisoned(),
            "rmp #803: a back-to-back re-poisoning must be THROTTLED, not repaired again immediately \
             — otherwise an abort-heavy workload on an indexed property pays a full O(store) rebuild \
             of every index on every command"
        );

        // LIVENESS: it must still be repaired shortly after. A throttle that never fires again is just
        // the original defect wearing a different name.
        let mut drains = 0;
        while coord.ft_spatial_poisoned() && drains < 64 {
            drain(&mut coord);
            drains += 1;
        }
        assert!(
            !coord.ft_spatial_poisoned(),
            "the throttled repair must still fire: still poisoned after {drains} further commands"
        );

        // THE QUANTITATIVE PIN. The repair is a full O(store) rebuild of every index, so its RATE must
        // track the FAULT, never the traffic. Drive a workload that re-poisons on EVERY command — the
        // worst case — and require the rebuild count to stay a small fraction of it.
        const ROUNDS: u64 = 300;
        let before = coord.ft_poison_repairs();
        for _ in 0..ROUNDS {
            poison(&mut coord);
            drain(&mut coord);
        }
        let repairs = coord.ft_poison_repairs() - before;
        assert!(
            repairs * 4 < ROUNDS,
            "rmp #803: {repairs} full-store rebuilds over {ROUNDS} re-poisoning commands. The repair \
             rate must be proportionate to the FAULT, not to the traffic — one rebuild per command \
             drags the whole store through the buffer pool on every write and is a worse regression \
             than the degradation it repairs"
        );
    }

    #[test]
    fn an_unrelated_aborting_statement_cannot_inherit_leaked_dirty_flags() {
        let coord = fresh_coord();
        let seed = coord.begin_serializable();
        run_stmt(&coord, seed, "CREATE (:Product {id: 1, name: 'Widget 1'})");
        coord.commit(seed).expect("seed commits");
        coord
            .create_text_index("tx_name", "Product", "name", false)
            .expect("create text index");
        assert!(
            !coord.ft_spatial_poisoned(),
            "precondition: a fresh engine with a freshly built index is not poisoned"
        );

        // PLANT THE RESIDUE, exactly as a build that bailed after mutating would leave it: both the
        // dirty bit and the `removed` companion. `mark_ft_spatial_mutated_inflight` is the public
        // method that produces precisely that pair, so this is the real state, not an approximation of
        // it. (Six drivers could reach it; the `removed` half needs a read fault, which is why this
        // test plants it rather than staging a fault-injection scenario to produce one bit.)
        coord.index.borrow_mut().mark_ft_spatial_mutated_inflight();

        // A transaction that touches a label with NO index of any kind — and then aborts.
        let unrelated = coord.begin_serializable();
        run_stmt(&coord, unrelated, "CREATE (:Unrelated {x: 1})");
        coord.rollback(unrelated).expect("the unrelated txn aborts");

        assert!(
            !coord.ft_spatial_poisoned(),
            "rmp #803: a transaction that touched NO indexed property inherited a build's leaked \
             dirty flags, was recorded as a full-text/spatial REMOVER, and its abort then poisoned the \
             DB-wide freshness marker — permanently degrading every TEXT, FULLTEXT and SPATIAL index \
             in the database. The statement seam must discard residue before doing any work."
        );
    }
}

#[cfg(test)]
mod index_entry_rollback_wiring_992 {
    use graphus_core::Value;
    use graphus_io::MemBlockDevice;
    use graphus_storage::{Namespace, RecordStore};
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn run_stmt(coord: &Coord, txn: graphus_core::TxnId, src: &str) {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// Whether the coordinator's derived index currently offers `id` as a candidate for
    /// `(:Person).age = value`. Reaches the coordinator's **private** index handle, which is the whole
    /// reason this test lives inline instead of in `tests/index_mvcc_rollback_992.rs`: the effect of
    /// `rmp` #992 is on the index's *content*, and no query can observe it — every consumer re-checks
    /// each candidate against its own MVCC snapshot, so a leftover entry is a false positive that gets
    /// filtered either way.
    fn index_offers(coord: &Coord, label: u32, prop: u32, value: i64, id: u64) -> bool {
        coord
            .index
            .borrow_mut()
            .seek_node_property_eq(label, prop, &Value::Integer(value))
            .expect("the index is registered, so the seek must not decline")
            .contains(&id)
    }

    fn tokens(coord: &Coord) -> (u32, u32) {
        let store = coord.store.borrow();
        (
            store
                .token_id(Namespace::Label, "Person")
                .expect("label token"),
            store
                .token_id(Namespace::PropKey, "age")
                .expect("prop token"),
        )
    }

    /// **`TxnCoordinator::rollback` really performs the index-entry undo** (`rmp` #992, AC1).
    ///
    /// `tests/index_mvcc_rollback_992.rs` proves the mechanism over the same statement seam the
    /// coordinator builds; this proves the coordinator is *wired* to it — that `abort` drains the
    /// transaction's log and applies it, rather than the two `IndexSet` methods sitting there with no
    /// production caller, which is exactly the state the four `remove` APIs were in before this task.
    #[test]
    fn rollback_removes_the_index_entries_the_transaction_created() {
        let coord = fresh_coord();
        let seed = coord.begin_serializable();
        run_stmt(&coord, seed, "CREATE (:Person {age: 30})");
        coord.commit(seed).expect("seed commits");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord);

        // A transaction whose CREATE the index picks up eagerly, at write time.
        let writer = coord.begin_serializable();
        run_stmt(&coord, writer, "CREATE (:Person {age: 41})");
        let ghost = coord
            .index
            .borrow_mut()
            .seek_node_property_eq(l, k, &Value::Integer(41))
            .expect("registered")
            .first()
            .copied()
            .expect("precondition: the open write must be indexed, or there is nothing to undo");

        coord.rollback(writer).expect("rollback");

        assert!(
            !index_offers(&coord, l, k, 41, ghost),
            "the coordinator's rollback did not undo the index entry the transaction created"
        );
        // ... and the committed row's entry, which the same transaction never created, is untouched.
        let survivor = coord
            .index
            .borrow_mut()
            .seek_node_property_eq(l, k, &Value::Integer(30))
            .expect("registered");
        assert_eq!(
            survivor.len(),
            1,
            "the committed `age = 30` entry must survive the rollback"
        );
    }

    /// **An index DDL between the write and the rollback RETAINS the entry** — measured, because a
    /// neighbouring test's premise depends on it.
    ///
    /// `tests/index_rebuild_label.rs::a_rolled_back_create_is_not_resurrected_by_a_retained_label_entry`
    /// is built on the label entry surviving the rollback so the query-path re-check has something to
    /// reject. `rmp` #992 could have inverted that premise silently and left the test passing while
    /// testing nothing. It does not: the DDL drives `rebuild_index` -> `IndexSet::clear`, which drops
    /// every open transaction's undo log, so the rollback afterwards removes nothing and the entry is
    /// retained exactly as before. This pins the mechanism that keeps that test meaningful.
    #[test]
    fn an_index_ddl_between_the_write_and_the_rollback_retains_the_entry() {
        let coord = fresh_coord();
        let seed = coord.begin_serializable();
        run_stmt(&coord, seed, "CREATE (:Person {age: 30})");
        coord.commit(seed).expect("seed commits");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord);

        let writer = coord.begin_serializable();
        run_stmt(&coord, writer, "CREATE (:Person {age: 41})");
        let ghost = coord
            .index
            .borrow_mut()
            .seek_node_property_eq(l, k, &Value::Integer(41))
            .expect("registered")
            .first()
            .copied()
            .expect("precondition: the open write is indexed");

        // The production route to a full `clear` + rebuild, on an unrelated index.
        coord
            .create_point_rel_index("widget_at", "WIDGET", "at", false)
            .expect("unrelated index DDL");
        coord.rollback(writer).expect("rollback");

        assert!(
            index_offers(&coord, l, k, 41, ghost),
            "an intervening rebuild must leave the entry RETAINED — a log taken before the wipe \
             names keys the refill re-creates from COMMITTED versions, so replaying it could only \
             destroy committed state. Retention is the safe direction and the pre-#992 behaviour."
        );
    }

    /// The commit half of the wiring: `TxnCoordinator::commit` frees the bookkeeping and undoes
    /// nothing, so a later unrelated rollback cannot reach a committed transaction's entries.
    #[test]
    fn commit_keeps_the_index_entries_and_frees_the_log() {
        let coord = fresh_coord();
        let seed = coord.begin_serializable();
        run_stmt(&coord, seed, "CREATE (:Person {age: 30})");
        coord.commit(seed).expect("seed commits");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord);

        let writer = coord.begin_serializable();
        run_stmt(&coord, writer, "CREATE (:Person {age: 41})");
        coord.commit(writer).expect("commit");

        let after = coord
            .index
            .borrow_mut()
            .seek_node_property_eq(l, k, &Value::Integer(41))
            .expect("registered");
        assert_eq!(after.len(), 1, "a committed write's entry must survive");

        // An unrelated rollback afterwards must not disturb it.
        let other = coord.begin_serializable();
        run_stmt(&coord, other, "CREATE (:Person {age: 7})");
        coord.rollback(other).expect("rollback");
        assert_eq!(
            coord
                .index
                .borrow_mut()
                .seek_node_property_eq(l, k, &Value::Integer(41))
                .expect("registered")
                .len(),
            1,
            "an unrelated rollback removed a committed transaction's entry"
        );
    }
}

/// **The version GC collects the derived-index entries dead versions leave behind** (`rmp` #992,
/// AC2), driven through the real [`TxnCoordinator`].
///
/// These live inline for the same reason the rollback-wiring module above does: what `rmp` #992
/// changes is the index's **content**, and the coordinator's index handle is private. The headline
/// test is the acceptance criterion itself — index size against the number of versions of a rewritten
/// key — measured before and after the pass rather than asserted qualitatively.
#[cfg(test)]
mod index_gc_collection_992 {
    use graphus_core::Value;
    use graphus_io::MemBlockDevice;
    use graphus_storage::{Namespace, RecordStore};
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    /// Runs `src` in its own committed transaction.
    fn commit_stmt(coord: &mut Coord, src: &str) {
        let txn = coord.begin_serializable();
        run_stmt(coord, txn, src);
        coord.commit(txn).expect("commit");
    }

    fn run_stmt(coord: &Coord, txn: graphus_core::TxnId, src: &str) {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    fn tokens(coord: &Coord, label: &str, prop: &str) -> (u32, u32) {
        let store = coord.store.borrow();
        (
            store
                .token_id(Namespace::Label, label)
                .expect("label token"),
            store
                .token_id(Namespace::PropKey, prop)
                .expect("prop token"),
        )
    }

    /// How many entries the `(label, prop)` node-property index holds right now.
    fn entries(coord: &Coord, label: u32, prop: u32) -> usize {
        coord
            .index
            .borrow_mut()
            .node_property_entry_count(label, prop)
            .expect("the index is registered")
    }

    fn index_offers(coord: &Coord, label: u32, prop: u32, value: i64, id: u64) -> bool {
        coord
            .index
            .borrow_mut()
            .seek_node_property_eq(label, prop, &Value::Integer(value))
            .expect("the index is registered, so the seek must not decline")
            .contains(&id)
    }

    /// **The acceptance criterion, measured** (`rmp` #992, AC2): rewriting one indexed key `N` times
    /// grows the index by `N`, and a GC pass takes it back to **one** entry — the value in place.
    ///
    /// The measurement is the point. "The index stops growing with the version count" is a claim about
    /// a number, so the test records the number before the pass (which must be `N + 1`, or the growth
    /// this task removes was never reproduced) and after it (which must be `1`, independent of `N`).
    /// Running it at two values of `N` is what turns "it shrank" into "it no longer depends on `N`".
    #[test]
    fn the_index_stops_growing_with_the_number_of_versions_of_a_rewritten_key() {
        for versions in [8usize, 64] {
            let mut coord = fresh_coord();
            commit_stmt(&mut coord, "CREATE (:Person {name: 'p', age: 0})");
            coord
                .create_node_property_index("Person", "age")
                .expect("create index");
            let (l, k) = tokens(&coord, "Person", "age");

            for v in 1..=versions {
                commit_stmt(
                    &mut coord,
                    &format!("MATCH (n:Person) SET n.age = {v} RETURN n"),
                );
            }

            let before = entries(&coord, l, k);
            assert_eq!(
                before,
                versions + 1,
                "PRECONDITION: the defect must be reproduced first — {versions} rewrites over the \
                 initial value must leave {} entries, one per distinct value ever written",
                versions + 1
            );

            let report = coord.gc().expect("gc pass");
            assert!(
                report.dead_index_keys > 0,
                "NON-VACUITY: the pass must have reported dead keys, or nothing below exercises the \
                 collection at all"
            );

            let after = entries(&coord, l, k);
            assert_eq!(
                after, 1,
                "after GC the index must hold exactly the value in place, independent of the \
                 {versions} versions that preceded it (held {before} before the pass)"
            );
            assert!(
                index_offers(&coord, l, k, versions as i64, 1),
                "the surviving entry must be the LIVE value, not an arbitrary one"
            );
        }
    }

    /// **The re-check has teeth**: a value an older version stops holding but the **live** version
    /// still holds is not collected.
    ///
    /// `SET age = 31` then `SET age = 30` kills a version holding `30` while `30` is exactly what the
    /// node still has. Removing it on the strength of the dead key alone would delete a live row's
    /// only entry — a false negative for every future seek, which no re-check can resurrect. This is
    /// the case the superset-polarity witness exists for.
    #[test]
    fn a_value_the_live_version_still_holds_is_never_collected() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person {age: 30})");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord, "Person", "age");

        commit_stmt(&mut coord, "MATCH (n:Person) SET n.age = 31 RETURN n");
        commit_stmt(&mut coord, "MATCH (n:Person) SET n.age = 30 RETURN n");

        let report = coord.gc().expect("gc pass");
        assert!(
            report.dead_index_keys > 0,
            "NON-VACUITY: the pass must report the dead `30` and `31` versions"
        );

        assert!(
            index_offers(&coord, l, k, 30, 1),
            "the LIVE value's entry was collected: a dead version held `30`, but so does the node"
        );
        assert!(
            !index_offers(&coord, l, k, 31, 1),
            "the genuinely dead `31` entry survived, so the collection did nothing"
        );
        assert_eq!(
            entries(&coord, l, k),
            1,
            "exactly one entry must remain — the live value"
        );
    }

    /// **An open reader stops the collection.** The GC watermark is the oldest open snapshot, so a
    /// version a live reader can still reconstruct is not reclaimed — and its index entry therefore
    /// stays. Without this the collection would be a *destruction* path racing live readers.
    #[test]
    fn an_open_reader_keeps_the_versions_and_their_entries() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person {age: 30})");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord, "Person", "age");

        let reader = coord.begin_serializable();
        commit_stmt(&mut coord, "MATCH (n:Person) SET n.age = 31 RETURN n");
        assert_eq!(
            entries(&coord, l, k),
            2,
            "precondition: two versions indexed"
        );

        let pinned = coord.gc().expect("gc while the reader is open");
        assert_eq!(
            pinned.dead_index_keys, 0,
            "a version the open reader can still reconstruct must not be reported dead"
        );
        assert_eq!(
            entries(&coord, l, k),
            2,
            "the open reader's version lost its index entry"
        );

        coord.rollback(reader).expect("reader retires");
        coord.gc().expect("gc after the reader retires");
        assert_eq!(
            entries(&coord, l, k),
            1,
            "once the reader is gone the dead version's entry must be collected"
        );
    }

    /// **A reclaimed node leaves nothing behind**: its label entry and its property entries go with
    /// the record.
    ///
    /// A `DELETE` only tombstones, so the entries stay while an older snapshot can still see the node
    /// — they are false positives the re-check drops. Physical reclamation is different: the slot goes
    /// back on the free list and the next allocation gives that id to a **different** entity, at which
    /// point a leftover entry stops being filterable.
    #[test]
    fn a_reclaimed_node_leaves_no_entry_in_the_index() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person {age: 30})");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord, "Person", "age");
        assert_eq!(
            entries(&coord, l, k),
            1,
            "precondition: the node is indexed"
        );
        let labels_before = coord.index.borrow_mut().label_entry_count();
        assert!(labels_before > 0, "precondition: the label entry exists");

        commit_stmt(&mut coord, "MATCH (n:Person) DELETE n");
        assert_eq!(
            entries(&coord, l, k),
            1,
            "PRECONDITION: a tombstone alone must NOT remove the entry — if it did, this test would \
             be measuring the delete path rather than the reclamation path"
        );

        let report = coord.gc().expect("gc pass");
        assert!(
            report.reclaimed > 0,
            "NON-VACUITY: the pass must have physically reclaimed the node"
        );
        assert_eq!(
            entries(&coord, l, k),
            0,
            "the reclaimed node's property entry survived its record"
        );
        assert_eq!(
            coord.index.borrow_mut().label_entry_count(),
            labels_before - 1,
            "the reclaimed node's label entry survived its record"
        );
    }

    /// **A removed label takes its index entries with it** — both the `(label, node)` entry and the
    /// `(label, prop, value, node)` entries filed under it, while the node and the property live on.
    #[test]
    fn a_removed_label_takes_its_index_entries_with_it() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person:Staff {age: 30})");
        coord
            .create_node_property_index("Staff", "age")
            .expect("create index");
        let (staff, k) = tokens(&coord, "Staff", "age");
        assert_eq!(
            entries(&coord, staff, k),
            1,
            "precondition: indexed under :Staff"
        );

        commit_stmt(&mut coord, "MATCH (n:Staff) REMOVE n:Staff RETURN n");
        assert_eq!(
            entries(&coord, staff, k),
            1,
            "PRECONDITION: the write path only inserts, so the stale entry must still be there"
        );

        let report = coord.gc().expect("gc pass");
        assert!(
            report.dead_index_keys > 0,
            "NON-VACUITY: the freed `AddLabel` delta must be reported"
        );
        assert_eq!(
            entries(&coord, staff, k),
            0,
            "the `(:Staff).age` entry survived the label removal"
        );
        assert!(
            !coord.index.borrow_mut().seek_label(staff).contains(&1),
            "the `(:Staff, n)` label entry survived the label removal"
        );
        // The node itself is untouched: it still exists, still has `age`, and still has `:Person`.
        let (person, _) = tokens(&coord, "Person", "age");
        assert!(
            coord.index.borrow_mut().seek_label(person).contains(&1),
            "the label the node KEPT was collected"
        );
    }

    /// **An UNCOMMITTED writer's value is never collected** — the case the open-reader test does not
    /// cover, and the one where the two halves of the safety argument have to hold together.
    ///
    /// A writer that has set `age = 31` and not committed is protected twice over, and neither guard
    /// is visible from the other's side: the version GC frees an entity's undo chain only when EVERY
    /// delta on it is dead, so an in-flight delta keeps the whole chain — including the historical
    /// `30` — from being reported at all; and the witness is a superset scan, which reads through an
    /// open writer's delta rather than around it. Belt and braces, deliberately, because this is the
    /// interleaving the multi-writer layers will multiply.
    #[test]
    fn an_uncommitted_writers_value_is_never_collected() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person {age: 30})");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        let (l, k) = tokens(&coord, "Person", "age");

        let writer = coord.begin_serializable();
        run_stmt(&coord, writer, "MATCH (n:Person) SET n.age = 31 RETURN n");
        assert_eq!(
            entries(&coord, l, k),
            2,
            "PRECONDITION: the uncommitted write is already in the tree — the index is a candidate \
             structure and indexes eagerly, which is exactly why the collection must be careful here"
        );

        let report = coord.gc().expect("gc with an uncommitted writer open");
        assert_eq!(
            report.dead_index_keys, 0,
            "an entity with an in-flight delta on its chain must report nothing: the chain is freed \
             all-or-nothing, and this one is not all dead"
        );
        assert_eq!(
            entries(&coord, l, k),
            2,
            "neither the committed `30` nor the uncommitted `31` may be collected"
        );

        // And the writer can still commit and be found through the index it would have lost.
        coord.commit(writer).expect("commit the writer");
        assert!(
            index_offers(&coord, l, k, 31, 1),
            "the committed value's entry was collected while it was still uncommitted"
        );
    }

    /// **The fan-out reaches every label partition the entity is filed under.** A dead key names a
    /// property, never the label it was indexed beneath, and `reindex_node` files one entry per
    /// covered label the node carries — so a collection that stopped at the first partition would
    /// leave the others growing with the version count, invisibly to any single-label test.
    #[test]
    fn a_dead_value_is_collected_from_every_label_partition_it_was_filed_under() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person:Staff {age: 0})");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index on :Person");
        coord
            .create_node_property_index("Staff", "age")
            .expect("create index on :Staff");
        let (person, k) = tokens(&coord, "Person", "age");
        let (staff, _) = tokens(&coord, "Staff", "age");

        for v in 1..=6 {
            commit_stmt(
                &mut coord,
                &format!("MATCH (n:Person) SET n.age = {v} RETURN n"),
            );
        }
        assert_eq!(entries(&coord, person, k), 7, "PRECONDITION: :Person grew");
        assert_eq!(entries(&coord, staff, k), 7, "PRECONDITION: :Staff grew");

        coord.gc().expect("gc pass");

        assert_eq!(entries(&coord, person, k), 1, "the :Person partition");
        assert_eq!(
            entries(&coord, staff, k),
            1,
            "the :Staff partition was left growing — the fan-out stopped at the first match"
        );
        assert!(index_offers(&coord, person, k, 6, 1));
        assert!(index_offers(&coord, staff, k, 6, 1));
    }

    /// **A relationship-property index is collected the same way** — the mirror of the headline test
    /// over the relationship dimension, so the `StoreKind::Rel` arm is not carried by inspection.
    #[test]
    fn a_rewritten_relationship_property_stops_growing_the_index() {
        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:P)-[:RATED {score: 0}]->(:P)");
        coord
            .create_rel_property_index_named(None, "RATED", "score", false)
            .expect("create index");
        let store_tokens = {
            let store = coord.store.borrow();
            (
                store
                    .token_id(Namespace::RelType, "RATED")
                    .expect("type token"),
                store
                    .token_id(Namespace::PropKey, "score")
                    .expect("prop token"),
            )
        };
        let (t, k) = store_tokens;

        for v in 1..=8 {
            commit_stmt(
                &mut coord,
                &format!("MATCH ()-[r:RATED]->() SET r.score = {v} RETURN r"),
            );
        }
        assert_eq!(
            coord
                .index
                .borrow_mut()
                .rel_property_entry_count(t, k)
                .expect("registered"),
            9,
            "PRECONDITION: nine distinct values must be indexed"
        );

        coord.gc().expect("gc pass");
        assert_eq!(
            coord
                .index
                .borrow_mut()
                .rel_property_entry_count(t, k)
                .expect("registered"),
            1,
            "the relationship-property index still grows with the version count"
        );
    }

    /// **A commit landing between the witness and the removal is detected, because the clock is read
    /// under the hold that removes** (`rmp` #1022).
    ///
    /// # What this proves, and what it deliberately does not
    ///
    /// The scenario the acceptance criterion describes in full — one writer creating an entity in a
    /// just-reclaimed slot while another rewrites a value, both during a collection — cannot be built
    /// today: the engine has one writer thread, which is exactly what `rmp` #1013 changes and exactly
    /// why this task blocks it. What CAN be built, and is what the fix actually turns on, is the
    /// detection itself: a real thread advances the commit clock while a collection runs, and the
    /// collection must never remove entries across an advance it did not see.
    ///
    /// The clock is a genuine seam, not a mock: it is the same `Arc<AtomicU64>` a commit bumps
    /// (`RecordStore::next_commit_ts`), reached through the same `commit_clock` handle the collector
    /// uses. Advancing it from another thread is what a concurrent commit does to the value this
    /// decision reads.
    ///
    /// Non-vacuity is asserted, not assumed: the run is required to have actually raced (the clock
    /// moved during the collection at least once), otherwise the assertion below never faced anything.
    #[test]
    fn a_clock_advance_during_a_collection_is_never_removed_across_1022() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Barrier};

        let mut coord = fresh_coord();
        commit_stmt(&mut coord, "CREATE (:Person {name: 'p', age: 0})");
        coord
            .create_node_property_index("Person", "age")
            .expect("create index");
        for v in 1..=64 {
            commit_stmt(
                &mut coord,
                &format!("MATCH (n:Person) SET n.age = {v} RETURN n"),
            );
        }

        let clock: Arc<AtomicU64> = coord.store.borrow().commit_clock();
        let advances = Arc::new(AtomicU64::new(0));
        // Two rendezvous points, so the advance happens strictly INSIDE the interval: the collector
        // waits for the committer, the committer advances the clock, and only then is the collector
        // released. A free-running ticker cannot express that, and a test built on one passes under
        // the defect (verified).
        let arrived = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));

        let committer = {
            let clock = Arc::clone(&clock);
            let advances = Arc::clone(&advances);
            let arrived = Arc::clone(&arrived);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                // One advance per batch the collector decides.
                loop {
                    arrived.wait();
                    if advances.load(Ordering::Acquire) == u64::MAX {
                        break;
                    }
                    // Exactly what a concurrent commit does to the value this decision reads.
                    clock.fetch_add(1, Ordering::AcqRel);
                    advances.fetch_add(1, Ordering::Release);
                    done.wait();
                }
            })
        };

        {
            let arrived = Arc::clone(&arrived);
            let done = Arc::clone(&done);
            // The hook is installed in a process-wide static, but the rendezvous it drives has exactly
            // two participants: this test's `gc()` and its committer. Any OTHER test in this binary
            // that runs a collection while the hook is installed becomes an uninvited third, and the
            // barrier then pairs the wrong two threads — our pass sails through without the clock
            // having advanced and removes entries the gate exists to see abandoned. That is not
            // hypothetical: it is how this test failed once the suite began running binaries
            // concurrently (`rmp` #1044), and it could always have failed, since this binary runs its
            // own tests in parallel already.
            //
            // Scoping the hook to the installing thread makes it ours alone. A foreign collection
            // returns immediately and is neither paused nor counted, which is exactly the isolation
            // the static cannot provide by itself.
            let owner = std::thread::current().id();
            let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if std::thread::current().id() != owner {
                    return; // another test's collection: not the interval this gate pins
                }
                arrived.wait();
                done.wait();
            });
            *crate::coordinator::BETWEEN_WITNESS_AND_REMOVAL
                .lock()
                .unwrap() = Some(hook);
        }

        let removed_before = coord.index_collection_totals().entries_removed;
        let report = coord.gc().expect("gc pass");
        let removed = coord.index_collection_totals().entries_removed - removed_before;

        // Tear the rendezvous down before asserting, so a failure does not leave the committer parked.
        *crate::coordinator::BETWEEN_WITNESS_AND_REMOVAL
            .lock()
            .unwrap() = None;
        advances.store(u64::MAX, Ordering::Release);
        arrived.wait();
        committer.join().expect("committer panicked");

        assert!(
            report.dead_index_keys > 0,
            "NON-VACUITY: the pass must have reported dead keys, or the collection never ran"
        );

        // THE property. Every batch was decided with a commit landing between reading the witness and
        // removing, so every batch must have been abandoned. Reading the clock while the store was
        // still held — the ordering this task replaced — misses that advance entirely and removes
        // entries a committed version warrants. Those kinds are candidate-only, so a missing posting
        // is a lost row no re-check resurrects.
        assert_eq!(
            removed, 0,
            "entries were removed although a commit landed between the witness and the removal: the \
             clock was read too early to see it (`rmp` #1022)"
        );
    }
}

#[cfg(test)]
mod coordinator_shareable_1033 {
    /// **The barrier layer 7b removes, stated as a type bound** (`rmp` #1033).
    ///
    /// Until this layer the coordinator's every mutator took `&mut self`, so `Arc<TxnCoordinator>`
    /// could be *held* by several threads but used by none of them concurrently — the outer Mutex was
    /// what made it usable at all, and it serialised whole statements. With the store, the catalog, the
    /// index-build queues and the open-transaction table each behind their own latch, and the counters
    /// atomic, the coordinator is shareable on its own terms.
    ///
    /// A compile-time assertion: it fails to BUILD, not to run, if a `&mut self` mutator or a non-`Sync`
    /// field ever comes back.
    #[test]
    fn the_coordinator_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<
            super::TxnCoordinator<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>,
        >();
    }
}
