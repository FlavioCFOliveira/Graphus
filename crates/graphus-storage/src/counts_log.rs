//! **Logged cardinality counters** (`rmp` #1066): the durable delta record, the set of
//! transactions already folded into the catalogue, and the replay that puts the two together.
//!
//! # Why the counters are logged as deltas
//!
//! [`Statistics`]'s six live-record counters are not advisory: since `rmp` #866 a Cypher `count()`
//! is answered from them, and nothing recomputes them from a scan at `open`. A wrong value is a
//! wrong query answer that survives every restart.
//!
//! They used to reach disk only as part of the **whole catalogue image** that
//! `RecordStore::checkpoint_meta` rewrites at every commit, and that cannot be made exact under
//! concurrent committers. A checkpoint samples the image and writes it later, holding nothing in
//! between, so a transaction that commits inside that interval is absent from the image — and if
//! that image lands last, its rows never reach the durable catalogue. `rmp` #1055 measured two
//! distinct shapes of this on the deterministic scheduler
//! (`graphus-dst`'s `det_scheduler_checkpoint_inversion_1055`), and measured that **electing the
//! newest image fixes neither**: on all ten failing seeds the newest image sampled is itself
//! incomplete. Ordering is not the lever.
//!
//! A delta has no such failure mode. It names only what its own transaction changed, so no
//! committer's record can erase another's, and the durable answer is the checkpointed base plus
//! every delta not yet folded into it.
//!
//! # The reference, and the one thing that had to be measured in it
//!
//! Neo4j is the only production engine among those surveyed (Neo4j, PostgreSQL, InnoDB, Memgraph)
//! that keeps an **exact**, durable cardinality under concurrent commits, and it does it by logging
//! the deltas: `GBPTreeGenericCountsStore` applies *relative* values and reads absolute ones, over
//! changes accumulated per key in `CountsChanges`. Graphus needs the exact number for the reason
//! above; the other three declare their counter approximate and scan to answer.
//!
//! The load-bearing detail was read in that source rather than presumed. `TxIdInformation`
//! (`community/storage-engine-util/.../TxIdInformation.java:41-43`) decides "already applied" as
//! `txId <= highestGapFreeTxId || strayTxIds.contains(txId)` — a **gap-free prefix plus an explicit
//! set of the ids above it**, not the highest id seen. That distinction exists because appliers
//! finish out of order, and it is the same reason `rmp` #1062 had to make log order equal apply
//! order *per page*: where the two orders can differ, a prefix silently skips legitimate work. Here
//! there is no page to serialise on, so [`AppliedTxSet`] carries the set. The prefix inside it is a
//! **compaction of a contiguous run of ids that are each individually known to be applied**, which
//! preserves the set exactly; it is never advanced over an id that has not been seen.
//!
//! Inspiration only — no Neo4j code is reproduced here, and the encoding, the types and the replay
//! are this project's own.
//!
//! # What this layer does and does not do
//!
//! This is the **format and the recovery**. The write path is unchanged: `checkpoint_meta` still
//! persists the counters inside the catalogue image, and nothing in production emits a
//! [`RecordType::CountDelta`](graphus_wal::RecordType::CountDelta) record yet. Making a commit emit
//! its delta — and taking the counters out of the image, which is what finally closes `rmp` #1055 —
//! is `rmp` #1067.
//!
//! The invariant that ties the two halves together, and that #1067 inherits, is:
//!
//! > [`AppliedTxSet`] names exactly the transactions whose count deltas are already folded into the
//! > [`Statistics`] persisted beside it.
//!
//! The pair is persisted together, in one catalogue image, so it cannot be observed half-updated.

use std::collections::{BTreeMap, BTreeSet};

use graphus_core::TxnId;
use graphus_core::error::{GraphusError, Result};

use crate::meta::{CountKey, Statistics, read_u8, read_u32, read_u64};

/// The [`CountDelta`] payload layout this build writes and reads.
///
/// Framed inside the record because the record type alone says "this is a counter change", not
/// which shape of one. A future layout change bumps this and defines its own body; a payload
/// carrying an unknown version is refused rather than guessed at, exactly as an unreadable catalogue
/// image is (`05 §12.6`).
const COUNT_DELTA_PAYLOAD_VERSION: u8 = 1;

/// One transaction's pending, not-yet-committed change to the six live-record cardinality counters
/// of [`Statistics`] (`rmp` #866): a signed net delta per [`CountKey`].
///
/// Since `rmp` #1066 this is also the **durable wire form** of that change: it is what a
/// [`RecordType::CountDelta`](graphus_wal::RecordType::CountDelta) record carries
/// ([`encode`](Self::encode) / [`decode`](Self::decode)). One type serves both roles deliberately —
/// the thing a transaction accumulates in memory and the thing it will log are the same fact, and
/// two types would be two chances to disagree about it.
///
/// # Why this needs none of `SchemaUndo`'s machinery
///
/// The catalog-DDL undo of `rmp` #734 needs a per-entry `seq` generation, an owner witness and a
/// predecessor-chain splice, because a DDL entry holds an **opaque value** on shared unversioned
/// state: restoring it means "put back what was there before *me*", which is only meaningful while
/// nobody else has written since, and out-of-order aborts break the chain.
///
/// Counters are not values, they are **counts**: integer addition is commutative and associative,
/// and every delta is exactly invertible by its negation. `committed + d₁ + d₂ − d₁` equals
/// `committed + d₂` no matter what order the transactions arrive, abort or commit in — so there is
/// no last-writer question to answer, no generation to witness, no ABA to distinguish and no chain
/// to splice. That is the whole reason this type is a handful of maps rather than an undo log, and
/// it is worth stating because the neighbouring `SchemaUndo` looks like the template to copy and
/// is not.
///
/// **That argument is about the deltas, not about applying them.** `Statistics`'s mutators saturate
/// at `0`, and saturation does not commute, so folding several deltas into a catalogue is only
/// order-independent if the arithmetic is done first and applied once — which is what
/// [`replay_count_deltas`] does, and why it exists as a separate function rather than a loop.
///
/// A create/delete pair inside one transaction nets to zero and is **pruned**, so
/// [`is_empty`](Self::is_empty) is exactly "this transaction has moved no counter", and the maps
/// stay bounded by the distinct labels/types the transaction actually touched (never by its row
/// count).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CountDelta {
    total_nodes: i64,
    total_relationships: i64,
    per_label: BTreeMap<u32, i64>,
    per_type: BTreeMap<u32, i64>,
    per_start_label_type: BTreeMap<(u32, u32), i64>,
    per_type_end_label: BTreeMap<(u32, u32), i64>,
}

impl CountDelta {
    /// Accumulates `delta` (`±1` from a single write on the live path; any signed value when a test
    /// or a decoded record builds one directly) under `key`.
    pub fn record(&mut self, key: CountKey, delta: i64) {
        match key {
            CountKey::TotalNodes => {
                self.total_nodes = self.total_nodes.saturating_add(delta);
            }
            CountKey::TotalRelationships => {
                self.total_relationships = self.total_relationships.saturating_add(delta);
            }
            CountKey::Label(token) => Self::accumulate(&mut self.per_label, token, delta),
            CountKey::RelType(token) => Self::accumulate(&mut self.per_type, token, delta),
            CountKey::StartLabelType(label, ty) => {
                Self::accumulate(&mut self.per_start_label_type, (label, ty), delta);
            }
            CountKey::TypeEndLabel(ty, label) => {
                Self::accumulate(&mut self.per_type_end_label, (ty, label), delta);
            }
        }
    }

    /// Adds `delta` to one keyed slot, **removing** the entry when it nets back to zero. The pruning
    /// is what makes "the map is empty" and "every delta is zero" the same statement, which
    /// [`is_empty`](Self::is_empty) — and therefore the checkpoint fast path — relies on.
    fn accumulate<K: Ord>(map: &mut BTreeMap<K, i64>, key: K, delta: i64) {
        match map.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let next = slot.get().saturating_add(delta);
                if next == 0 {
                    slot.remove();
                } else {
                    *slot.get_mut() = next;
                }
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                if delta != 0 {
                    slot.insert(delta);
                }
            }
        }
    }

    /// `true` when this transaction has moved no counter at all — the case for every read-only
    /// transaction, every pure property write, and every DDL statement.
    pub fn is_empty(&self) -> bool {
        self.total_nodes == 0
            && self.total_relationships == 0
            && self.per_label.is_empty()
            && self.per_type.is_empty()
            && self.per_start_label_type.is_empty()
            && self.per_type_end_label.is_empty()
    }

    /// Un-applies this delta from `stats`, i.e. applies its exact negation. Turns an image that
    /// **includes** this transaction's pending counts into one that excludes them, which is what both
    /// the rollback (withdraw my own) and the checkpoint (withdraw every open transaction's) need.
    pub(crate) fn withdraw_from(&self, stats: &mut Statistics) {
        stats.apply_count_delta(CountKey::TotalNodes, self.total_nodes.saturating_neg());
        stats.apply_count_delta(
            CountKey::TotalRelationships,
            self.total_relationships.saturating_neg(),
        );
        for (&token, &d) in &self.per_label {
            stats.apply_count_delta(CountKey::Label(token), d.saturating_neg());
        }
        for (&token, &d) in &self.per_type {
            stats.apply_count_delta(CountKey::RelType(token), d.saturating_neg());
        }
        for (&(label, ty), &d) in &self.per_start_label_type {
            stats.apply_count_delta(CountKey::StartLabelType(label, ty), d.saturating_neg());
        }
        for (&(ty, label), &d) in &self.per_type_end_label {
            stats.apply_count_delta(CountKey::TypeEndLabel(ty, label), d.saturating_neg());
        }
    }

    /// Serialises this delta into the payload of a
    /// [`RecordType::CountDelta`](graphus_wal::RecordType::CountDelta) record (`rmp` #1066).
    ///
    /// Deterministic: every map is a [`BTreeMap`], so the entries go out in key order and one delta
    /// always encodes to one byte string. That matters because these bytes are checksummed inside
    /// the log record and compared byte-for-byte by the round-trip tests.
    ///
    /// A **zero** delta is carried faithfully rather than dropped. The live path never produces one
    /// (`accumulate` prunes a slot that nets back to zero, and
    /// [`is_empty`](Self::is_empty) is the gate on logging at all), but this is a transport: whether
    /// a zero is meaningful is the producer's business, and a codec that silently rewrites its input
    /// cannot be round-trip tested.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 16
                + 4 * 4
                + (self.per_label.len() + self.per_type.len()) * 12
                + (self.per_start_label_type.len() + self.per_type_end_label.len()) * 16,
        );
        out.push(COUNT_DELTA_PAYLOAD_VERSION);
        out.extend_from_slice(&self.total_nodes.to_le_bytes());
        out.extend_from_slice(&self.total_relationships.to_le_bytes());
        encode_token_map(&mut out, &self.per_label);
        encode_token_map(&mut out, &self.per_type);
        encode_pair_map(&mut out, &self.per_start_label_type);
        encode_pair_map(&mut out, &self.per_type_end_label);
        out
    }

    /// Rebuilds a delta from a payload produced by [`encode`](Self::encode).
    ///
    /// Strict in both directions: a payload that is too short is truncation, and a payload with
    /// bytes left over is not one this build wrote. Neither is tolerated, because unlike the
    /// catalogue image — which is an append-only sequence of blocks where "the image ends here"
    /// legitimately means "an older writer" — this payload is wholly described by its version byte.
    /// A future layout arrives as a new `COUNT_DELTA_PAYLOAD_VERSION`, not as a longer body.
    ///
    /// # Errors
    /// Returns a storage error if the version byte is unknown, the payload is truncated, an entry
    /// count is not addressable by the bytes that follow it, or bytes remain after the last entry.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        let version = read_u8(bytes, &mut cur)?;
        if version != COUNT_DELTA_PAYLOAD_VERSION {
            return Err(GraphusError::Storage(format!(
                "WAL count-delta payload carries layout version {version}, which this build cannot \
                 read (it writes and reads version {COUNT_DELTA_PAYLOAD_VERSION}); a log written by \
                 a newer build must be recovered by that build"
            )));
        }
        let mut d = Self {
            total_nodes: read_i64(bytes, &mut cur)?,
            total_relationships: read_i64(bytes, &mut cur)?,
            ..Self::default()
        };
        d.per_label = decode_token_map(bytes, &mut cur, "per_label")?;
        d.per_type = decode_token_map(bytes, &mut cur, "per_type")?;
        d.per_start_label_type = decode_pair_map(bytes, &mut cur, "per_start_label_type")?;
        d.per_type_end_label = decode_pair_map(bytes, &mut cur, "per_type_end_label")?;
        if cur != bytes.len() {
            return Err(GraphusError::Storage(format!(
                "WAL count-delta payload has {} trailing byte(s) after a complete version-{} body; \
                 this build's layout is fully described by its version byte, so extra bytes mean \
                 corruption rather than a newer writer",
                bytes.len() - cur,
                COUNT_DELTA_PAYLOAD_VERSION
            )));
        }
        Ok(d)
    }

    /// Feeds every non-zero slot of this delta into `f` as a `(key, signed delta)` pair, in a fixed
    /// order. The one place that knows how the six slots map onto [`CountKey`], so the accumulator
    /// and any future consumer cannot disagree about it.
    fn for_each(&self, mut f: impl FnMut(CountKey, i64)) {
        if self.total_nodes != 0 {
            f(CountKey::TotalNodes, self.total_nodes);
        }
        if self.total_relationships != 0 {
            f(CountKey::TotalRelationships, self.total_relationships);
        }
        for (&token, &d) in &self.per_label {
            f(CountKey::Label(token), d);
        }
        for (&token, &d) in &self.per_type {
            f(CountKey::RelType(token), d);
        }
        for (&(label, ty), &d) in &self.per_start_label_type {
            f(CountKey::StartLabelType(label, ty), d);
        }
        for (&(ty, label), &d) in &self.per_type_end_label {
            f(CountKey::TypeEndLabel(ty, label), d);
        }
    }
}

/// The set of transactions whose count deltas are **already folded into** the [`Statistics`]
/// persisted alongside this set (`rmp` #1066).
///
/// # It is a set, and the prefix inside it is a compaction — not a watermark
///
/// The obvious cheap answer, "everything up to the highest id applied", is **unsound here**, and the
/// project has already paid for that lesson once: `rmp` #1062 had to make log order equal apply
/// order *per page* precisely because a conditional replay keyed on position skips work when the two
/// orders differ. With several engine workers there is no page, and no other serialisation point, to
/// make them agree — a transaction with a higher id can be applied while a lower one is still in
/// flight, and a watermark would then declare the lower one done. Neo4j reached the same conclusion
/// and for the same stated reason (`TxIdInformation.java:41-43`: `txId <= highestGapFreeTxId ||
/// strayTxIds.contains(txId)`).
///
/// So the representation is:
///
/// * [`frontier`](Self#structfield.frontier) — every id in `1..=frontier` is applied. It advances
///   **only** over ids that are individually in [`stray`](Self#structfield.stray), one at a time, so
///   it never covers an id that has not been seen. It is therefore a lossless compaction of a
///   contiguous run, and not an assumption about anything.
/// * [`stray`](Self#structfield.stray) — the applied ids **above** the frontier, explicitly.
///
/// `contains` is the union of the two, and `insert` is set union followed by that compaction. Both
/// are order-independent, which is what [`replay_count_deltas`] rests on.
///
/// # Growth, and what bounds it
///
/// A transaction id that is never applied — a loser, which logs no delta a replay may use — stalls
/// the frontier just below it, and every applied id above that point stays in `stray`. Under this
/// layer that is inert: nothing emits delta records, so the set is empty in every store this build
/// writes. It becomes real for `rmp` #1067, and the bound available there is that an id whose delta
/// record is no longer in the **retained** log can never be replayed again and can be dropped from
/// the set. Compacting against WAL reclamation is that task's, because reclamation is what its
/// checkpoint performs; it is named here so the property is not discovered later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedTxSet {
    /// Every transaction id in `1..=frontier` is applied. `0` means "no contiguous run yet"; the
    /// null id `TxnId(0)` is never a real transaction and is never a member.
    frontier: u64,
    /// Applied ids strictly above [`frontier`](Self#structfield.frontier).
    stray: BTreeSet<u64>,
}

impl AppliedTxSet {
    /// Whether `txn`'s count delta has already been folded into the counters this set accompanies.
    ///
    /// The null id `TxnId(0)` is never a member, whatever the frontier is: it names no
    /// transaction, so answering `true` for it would be a claim about nothing.
    #[must_use]
    pub fn contains(&self, txn: TxnId) -> bool {
        txn.0 != 0 && (txn.0 <= self.frontier || self.stray.contains(&txn.0))
    }

    /// Records that `txn`'s delta has been folded in, then absorbs any contiguous run now sitting
    /// immediately above the frontier.
    ///
    /// The compaction moves ids **out of** `stray` and **into** the frontier one at a time, so the
    /// set this represents is byte-for-byte the same set before and after. Inserting `10` into an
    /// empty set leaves the frontier at `0` and `10` in `stray`: it says nothing whatsoever about
    /// `1..=9`.
    ///
    /// Inserting the null id is a no-op, mirroring [`contains`](Self::contains).
    pub fn insert(&mut self, txn: TxnId) {
        if txn.0 == 0 || self.contains(txn) {
            return;
        }
        self.stray.insert(txn.0);
        while self.stray.remove(&(self.frontier + 1)) {
            self.frontier += 1;
        }
    }

    /// The highest id the contiguous applied run reaches (`0` when there is none). Diagnostics and
    /// tests only — a caller deciding whether a delta is applied must ask
    /// [`contains`](Self::contains), which is the whole point of the type.
    #[must_use]
    pub fn frontier(&self) -> u64 {
        self.frontier
    }

    /// The applied ids that sit above the frontier, ascending. Diagnostics and tests only.
    pub fn stray(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.stray.iter().copied()
    }

    /// Whether this set names no transaction at all — the state of every store this build writes,
    /// since nothing emits a delta record until `rmp` #1067.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frontier == 0 && self.stray.is_empty()
    }

    /// Serialises the set for the catalogue image. Deterministic: the frontier, then the strays in
    /// ascending order out of a [`BTreeSet`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.stray.len() * 8);
        out.extend_from_slice(&self.frontier.to_le_bytes());
        debug_assert!(
            self.stray.len() <= u32::MAX as usize,
            "applied-transaction stray set too large to frame"
        );
        out.extend_from_slice(&(self.stray.len() as u32).to_le_bytes());
        for &id in &self.stray {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    /// Rebuilds a set from [`encode`](Self::encode)'s bytes, starting at `*cur` and advancing it.
    ///
    /// # Errors
    /// Returns a storage error if the bytes are truncated, the entry count is not addressable by
    /// what follows it, or a stray id is not strictly above the frontier (which would make the
    /// image's two halves describe overlapping sets — a state `insert` cannot produce).
    pub fn decode(bytes: &[u8], cur: &mut usize) -> Result<Self> {
        let frontier = read_u64(bytes, cur)?;
        let n = read_u32(bytes, cur)? as usize;
        // Cap the reservation by the bytes that remain (each entry is 8 of them), so a forged count
        // cannot force a multi-gigabyte allocation before the per-entry reads reject it — the same
        // guard `Meta::decode_store` applies to a device-page map.
        let mut stray = BTreeSet::new();
        let addressable = bytes.len().saturating_sub(*cur) / 8;
        if n > addressable {
            return Err(GraphusError::Storage(format!(
                "applied-transaction set declares {n} stray id(s) but only {addressable} are \
                 addressable in the {} byte(s) that follow",
                bytes.len().saturating_sub(*cur)
            )));
        }
        for _ in 0..n {
            let id = read_u64(bytes, cur)?;
            if id <= frontier {
                return Err(GraphusError::Storage(format!(
                    "applied-transaction set lists stray id {id} at or below its gap-free frontier \
                     {frontier}; the frontier already covers it, so the image describes the same \
                     transaction twice"
                )));
            }
            stray.insert(id);
        }
        Ok(Self { frontier, stray })
    }
}

/// What one [`replay_count_deltas`] pass did — the witness a caller (or a non-vacuity assertion)
/// needs to tell "nothing to do" from "did nothing".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Records whose delta was folded in, and whose transaction was added to the applied set.
    pub applied: usize,
    /// Records skipped because their transaction was **already** in the applied set — either from a
    /// previous recovery whose result was checkpointed, or a duplicate within this batch.
    pub already_applied: usize,
}

/// Folds every not-yet-applied delta in `records` into `stats`, and records the transactions in
/// `applied` (`rmp` #1066).
///
/// The caller supplies only the records it may use: a delta belongs to the durable counters solely
/// when its transaction **committed**, and deciding that is recovery's job, not this function's.
///
/// # Why this is a fold-then-apply and not a loop
///
/// **Because a loop is not order-independent, and this must be.** `Statistics`'s mutators saturate
/// at `0` — `Statistics`'s `add_total` and `add_keyed` clamp a decrement that would go negative — and
/// saturation does not commute. The counterexample is ordinary, not contrived: transaction `A`
/// creates a node carrying label `L` and transaction `B`, later, deletes it. Against a base where
/// `L` counts `0`, the deltas are `+1` and `−1`, and applying them one at a time gives
///
/// ```text
///   base 0, then A(+1), then B(−1)  ->  0     (right)
///   base 0, then B(−1), then A(+1)  ->  1     (wrong: the −1 hit the rail at 0 and was lost)
/// ```
///
/// Summing first removes the intermediate state that could hit the rail. The fold is exact integer
/// addition, so it is commutative and associative by construction, and it cannot overflow: each
/// contributing value is an `i64` (`|d| < 2^63`) and a log holds fewer than `2^58` records (its
/// length is a `u64` and `MIN_RECORD_LEN` is 56 bytes), so `|Σd| < 2^121`, comfortably inside the
/// `i128` the accumulator uses. The single application that follows lands on a real state — the base
/// is the image the applied set describes, and adding every remaining committed delta to it is by
/// definition the committed truth — so it does not saturate either.
///
/// The three order-dependent-looking steps are each order-independent:
///
/// 1. **which records are admitted** — "distinct transactions not already in `applied`". A
///    transaction logs at most one delta record, so a second record bearing the same id is a
///    duplicate of the first and carries the same delta; which copy is admitted cannot matter.
/// 2. **the arithmetic** — exact integer addition, above.
/// 3. **the applied set** — set union, and [`AppliedTxSet::insert`]'s compaction preserves the set
///    exactly.
///
/// `tests::replay_is_independent_of_the_order_the_records_arrive_in` permutes a batch containing
/// exactly the counterexample above and asserts the result is identical, so the property is
/// demonstrated rather than claimed.
pub fn replay_count_deltas<'a, I>(
    stats: &mut Statistics,
    applied: &mut AppliedTxSet,
    records: I,
) -> ReplayOutcome
where
    I: IntoIterator<Item = (TxnId, &'a CountDelta)>,
{
    let mut outcome = ReplayOutcome::default();
    let mut total: BTreeMap<CountKey, i128> = BTreeMap::new();
    for (txn, delta) in records {
        if applied.contains(txn) {
            outcome.already_applied += 1;
            continue;
        }
        applied.insert(txn);
        outcome.applied += 1;
        delta.for_each(|key, d| {
            *total.entry(key).or_insert(0) += i128::from(d);
        });
    }
    for (key, sum) in total {
        // `sum` is a real cardinality change, so it fits an `i64` for any store that exists; clamp
        // rather than wrap if a defect ever produced one that did not, and catch it in debug — the
        // house rule `Statistics::add_total` already follows.
        let delta = i64::try_from(sum).unwrap_or_else(|_| {
            debug_assert!(false, "replayed count delta {sum} at {key:?} exceeds i64");
            if sum > 0 { i64::MAX } else { i64::MIN }
        });
        stats.apply_count_delta(key, delta);
    }
    outcome
}

// ------------------------------- payload primitives -------------------------------

fn encode_token_map(out: &mut Vec<u8>, map: &BTreeMap<u32, i64>) {
    debug_assert!(map.len() <= u32::MAX as usize, "count-delta map too large");
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (&token, &delta) in map {
        out.extend_from_slice(&token.to_le_bytes());
        out.extend_from_slice(&delta.to_le_bytes());
    }
}

fn encode_pair_map(out: &mut Vec<u8>, map: &BTreeMap<(u32, u32), i64>) {
    debug_assert!(map.len() <= u32::MAX as usize, "count-delta map too large");
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (&(a, b), &delta) in map {
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
        out.extend_from_slice(&delta.to_le_bytes());
    }
}

/// Reads a length-prefixed map, refusing a declared count the remaining bytes cannot address before
/// allocating for it (the forged-length OOM guard `Meta::decode_store` documents).
fn decode_token_map(bytes: &[u8], cur: &mut usize, which: &str) -> Result<BTreeMap<u32, i64>> {
    let n = read_count(bytes, cur, 12, which)?;
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let token = read_u32(bytes, cur)?;
        let delta = read_i64(bytes, cur)?;
        map.insert(token, delta);
    }
    Ok(map)
}

fn decode_pair_map(
    bytes: &[u8],
    cur: &mut usize,
    which: &str,
) -> Result<BTreeMap<(u32, u32), i64>> {
    let n = read_count(bytes, cur, 16, which)?;
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let a = read_u32(bytes, cur)?;
        let b = read_u32(bytes, cur)?;
        let delta = read_i64(bytes, cur)?;
        map.insert((a, b), delta);
    }
    Ok(map)
}

fn read_count(bytes: &[u8], cur: &mut usize, entry_len: usize, which: &str) -> Result<usize> {
    let n = read_u32(bytes, cur)? as usize;
    let addressable = bytes.len().saturating_sub(*cur) / entry_len;
    if n > addressable {
        return Err(GraphusError::Storage(format!(
            "WAL count-delta payload declares {n} `{which}` entries but only {addressable} are \
             addressable in the {} byte(s) that follow",
            bytes.len().saturating_sub(*cur)
        )));
    }
    Ok(n)
}

/// Signed counter delta, two's complement over the same eight little-endian bytes
/// [`read_u64`] reads. The cursor primitives themselves are [`crate::meta`]'s — see
/// [`crate::meta::take`] for why there is exactly one implementation of them.
fn read_i64(bytes: &[u8], cur: &mut usize) -> Result<i64> {
    Ok(read_u64(bytes, cur)? as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a delta by direct field assignment, so a test can express a shape the live path never
    /// produces (a zero that survives, an entry alongside an absent key).
    fn delta(
        total_nodes: i64,
        total_relationships: i64,
        per_label: &[(u32, i64)],
        per_type: &[(u32, i64)],
        per_start: &[((u32, u32), i64)],
        per_end: &[((u32, u32), i64)],
    ) -> CountDelta {
        CountDelta {
            total_nodes,
            total_relationships,
            per_label: per_label.iter().copied().collect(),
            per_type: per_type.iter().copied().collect(),
            per_start_label_type: per_start.iter().copied().collect(),
            per_type_end_label: per_end.iter().copied().collect(),
        }
    }

    // =============================================================================================
    // Criterion 1 — the record codec, including the edge cases.
    // =============================================================================================

    /// **A delta round-trips exactly**, including a negative delta, a zero delta, and an absent
    /// label key (`rmp` #1066, acceptance criterion 1).
    ///
    /// Each of the three edge cases is a different way for a codec to be quietly wrong:
    ///
    /// * **negative** — the counters are `u64` and the deltas are `i64`; a codec that framed them as
    ///   unsigned would turn `−1` into `2^64 − 1` and the replay would add an absurd cardinality
    ///   instead of removing a row;
    /// * **zero** — a codec that dropped zero entries (or that inserted one for an absent key) would
    ///   not be the identity, and the round-trip would be untestable as an equality;
    /// * **absent key** — an absent key and a zero count are the *same thing* to `Statistics` (the
    ///   zero-count invariant), but they are **not** the same thing in a delta: absent means "this
    ///   transaction did not touch this label", and materialising it would put a zero-valued entry
    ///   into a map whose emptiness the checkpoint fast path reads as "moved no counter".
    #[test]
    fn a_count_delta_round_trips_with_negative_zero_and_absent_keys() {
        let cases: Vec<(&str, CountDelta)> = vec![
            ("empty", CountDelta::default()),
            (
                "negative deltas throughout",
                delta(
                    -3,
                    -1,
                    &[(7, -2)],
                    &[(9, -1)],
                    &[((7, 9), -1)],
                    &[((9, 7), -1)],
                ),
            ),
            (
                "a zero delta beside a non-zero one",
                delta(0, 5, &[(1, 0), (2, 4)], &[], &[], &[((3, 1), 0)]),
            ),
            (
                "an absent label key: per_label empty, the others populated",
                delta(2, 0, &[], &[(4, 2)], &[((0, 4), 2)], &[]),
            ),
            (
                "the extremes of the signed range",
                delta(i64::MAX, i64::MIN, &[(u32::MAX, i64::MIN)], &[], &[], &[]),
            ),
        ];
        for (name, want) in cases {
            let bytes = want.encode();
            let got = CountDelta::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(got, want, "{name}: the payload did not round-trip");
            assert_eq!(
                got.encode(),
                bytes,
                "{name}: re-encoding a decoded payload produced different bytes, so the encoding is \
                 not canonical and a byte comparison of two catalogues cannot be trusted"
            );
        }
    }

    /// **An absent key stays absent, and a zero entry stays present** — the two halves of the edge
    /// case above, asserted on the maps themselves rather than through `PartialEq`.
    ///
    /// `PartialEq` on `BTreeMap` already distinguishes `{}` from `{1: 0}`, but the assertion above
    /// would still pass if BOTH sides collapsed the same way (an encoder that drops zeros and a
    /// decoder that never invents them agree with each other and are wrong together).
    #[test]
    fn an_absent_key_and_a_zero_entry_are_kept_apart_by_the_codec() {
        let absent = delta(0, 0, &[], &[], &[], &[]);
        let zeroed = delta(0, 0, &[(1, 0)], &[], &[], &[]);
        assert_ne!(
            absent, zeroed,
            "the fixture itself must distinguish the two"
        );
        let absent_back = CountDelta::decode(&absent.encode()).expect("decode absent");
        let zeroed_back = CountDelta::decode(&zeroed.encode()).expect("decode zeroed");
        assert!(
            absent_back.per_label.is_empty(),
            "an absent label key came back materialised as an entry"
        );
        assert_eq!(
            zeroed_back.per_label.get(&1),
            Some(&0),
            "a zero-valued entry was dropped by the codec, so it is not a faithful transport"
        );
        assert!(
            absent_back.is_empty(),
            "an all-absent delta must report itself empty"
        );
    }

    /// **A malformed payload is refused, never guessed at.** Each case is a distinct corruption the
    /// decoder must name rather than absorb.
    #[test]
    fn a_malformed_count_delta_payload_is_refused() {
        let good = delta(1, 0, &[(3, 1)], &[], &[], &[]).encode();

        let mut wrong_version = good.clone();
        wrong_version[0] = COUNT_DELTA_PAYLOAD_VERSION + 1;
        let err = CountDelta::decode(&wrong_version).expect_err("unknown layout version");
        assert!(
            format!("{err}").contains("layout version"),
            "the error must name the version: {err}"
        );

        for cut in 1..good.len() {
            assert!(
                CountDelta::decode(&good[..cut]).is_err(),
                "a payload truncated to {cut} of {} bytes decoded as if whole",
                good.len()
            );
        }

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(
            CountDelta::decode(&trailing).is_err(),
            "a payload with a trailing byte was accepted; this layout is fully described by its \
             version byte, so extra bytes are corruption"
        );

        // A forged entry count must be refused before it is allocated for.
        let mut forged = good.clone();
        let n_off = 1 + 16; // version + the two grand totals
        forged[n_off..n_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = CountDelta::decode(&forged).expect_err("forged entry count");
        assert!(
            format!("{err}").contains("addressable"),
            "the error must say the count is not addressable: {err}"
        );

        assert!(
            CountDelta::decode(&[]).is_err(),
            "an empty payload has no version byte and cannot be a delta"
        );
    }

    // =============================================================================================
    // Criterion 4 — the applied set is a set, not a prefix.
    // =============================================================================================

    /// **A high id applied alone says nothing about the ids below it** (`rmp` #1066, acceptance
    /// criterion 4).
    ///
    /// This is the test that fails if anyone replaces [`AppliedTxSet`] with a watermark. Under a
    /// "highest id applied" rule, inserting `10` would make `contains(5)` true and transaction 5's
    /// delta would be skipped for ever — a committed transaction's rows silently absent from a
    /// counter that `count()` is answered from. The frontier is allowed to advance **only** over ids
    /// individually inserted, which the second half asserts.
    #[test]
    fn the_applied_set_is_not_a_prefix_of_the_highest_id() {
        let mut set = AppliedTxSet::default();
        set.insert(TxnId(10));
        assert!(set.contains(TxnId(10)), "the id inserted must be a member");
        assert_eq!(
            set.frontier(),
            0,
            "inserting a single high id advanced the gap-free frontier over ids that were never \
             applied — that is a watermark, and it skips every legitimate delta below it"
        );
        for id in 1..10 {
            assert!(
                !set.contains(TxnId(id)),
                "id {id} was never inserted but the set claims it is applied; its delta would be \
                 skipped and its committed rows lost"
            );
        }
        // The frontier advances only as the gaps are genuinely filled, one id at a time.
        set.insert(TxnId(2));
        assert_eq!(set.frontier(), 0, "a gap at 1 still blocks the run");
        set.insert(TxnId(1));
        assert_eq!(
            set.frontier(),
            2,
            "1 and 2 are both applied and contiguous, so the run compacts to 2"
        );
        assert!(!set.contains(TxnId(3)));
        set.insert(TxnId(3));
        assert_eq!(set.frontier(), 3);
        // Filling the last gap absorbs 10 along with everything between.
        for id in 4..10 {
            set.insert(TxnId(id));
        }
        assert_eq!(
            set.frontier(),
            10,
            "with 1..=10 all applied the whole run compacts and the stray set empties"
        );
        assert_eq!(set.stray().count(), 0);
    }

    /// **The compaction preserves the set exactly**: whatever order ids arrive in, membership is the
    /// same, and so is the encoded image.
    #[test]
    fn the_applied_set_is_order_independent_and_canonical() {
        let ids = [7u64, 1, 3, 2, 9, 8];
        let mut forward = AppliedTxSet::default();
        for &id in &ids {
            forward.insert(TxnId(id));
        }
        let mut backward = AppliedTxSet::default();
        for &id in ids.iter().rev() {
            backward.insert(TxnId(id));
        }
        assert_eq!(forward, backward, "insertion order changed the set");
        assert_eq!(
            forward.encode(),
            backward.encode(),
            "insertion order changed the durable image"
        );
        for id in 1..=12u64 {
            assert_eq!(
                forward.contains(TxnId(id)),
                ids.contains(&id),
                "membership of {id} disagrees with the ids inserted"
            );
        }
        // Re-inserting a member changes nothing.
        let before = forward.clone();
        forward.insert(TxnId(3));
        forward.insert(TxnId(9));
        assert_eq!(before, forward, "re-inserting a member perturbed the set");
    }

    /// **The null transaction id is never a member**, whatever the frontier says.
    ///
    /// `TxnId(0)` is the null id, and a frontier of `0` on a fresh set makes the naive comparison
    /// `0 <= 0` true. A `contains(TxnId(0))` of `true` would make an empty set claim to have applied
    /// something.
    #[test]
    fn the_null_transaction_id_is_never_a_member() {
        let mut set = AppliedTxSet::default();
        assert!(set.is_empty());
        assert!(!set.contains(TxnId(0)));
        set.insert(TxnId(0));
        assert!(set.is_empty(), "inserting the null id created a member");
        set.insert(TxnId(1));
        assert!(!set.contains(TxnId(0)), "the frontier admitted the null id");
    }

    /// **The applied set round-trips**, and a self-contradictory image is refused.
    #[test]
    fn the_applied_set_round_trips_and_refuses_an_overlapping_image() {
        for ids in [
            vec![],
            vec![1u64],
            vec![1, 2, 3],
            vec![10],
            vec![1, 2, 5, 9, u64::MAX],
        ] {
            let mut want = AppliedTxSet::default();
            for id in &ids {
                want.insert(TxnId(*id));
            }
            let bytes = want.encode();
            let mut cur = 0usize;
            let got = AppliedTxSet::decode(&bytes, &mut cur).expect("decode");
            assert_eq!(got, want, "{ids:?} did not round-trip");
            assert_eq!(cur, bytes.len(), "{ids:?}: the decoder left bytes behind");
        }

        // frontier 5 with a stray of 3: `insert` can never build this, so it is corruption.
        let mut forged = Vec::new();
        forged.extend_from_slice(&5u64.to_le_bytes());
        forged.extend_from_slice(&1u32.to_le_bytes());
        forged.extend_from_slice(&3u64.to_le_bytes());
        let mut cur = 0usize;
        let err = AppliedTxSet::decode(&forged, &mut cur).expect_err("overlapping halves");
        assert!(
            format!("{err}").contains("frontier"),
            "the error must name the frontier: {err}"
        );

        // A forged stray count must be refused before it is allocated for.
        let mut forged = Vec::new();
        forged.extend_from_slice(&0u64.to_le_bytes());
        forged.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut cur = 0usize;
        let err = AppliedTxSet::decode(&forged, &mut cur).expect_err("forged stray count");
        assert!(
            format!("{err}").contains("addressable"),
            "the error must say the count is not addressable: {err}"
        );
    }

    // =============================================================================================
    // Criteria 2 and 3 — the replay.
    // =============================================================================================

    /// The batch every replay test below permutes: three transactions whose deltas, applied one at a
    /// time in the wrong order, hit the saturating rail.
    ///
    /// `A` creates a node with label `L` (the base counts `0` for `L`), `C` deletes it, and `B` is
    /// an unrelated increment that just widens the batch. Applying `C` before `A` drives `L` past
    /// `0`, where `Statistics::add_keyed` clamps — and a clamp is a lost decrement.
    fn saturating_batch() -> Vec<(TxnId, CountDelta)> {
        vec![
            (TxnId(1), delta(1, 0, &[(L, 1)], &[], &[], &[])),
            (TxnId(2), delta(1, 0, &[(M, 1)], &[], &[], &[])),
            (TxnId(3), delta(-1, 0, &[(L, -1)], &[], &[], &[])),
        ]
    }

    const L: u32 = 4;
    const M: u32 = 5;

    fn replay(batch: &[(TxnId, CountDelta)]) -> (Statistics, AppliedTxSet, ReplayOutcome) {
        let mut stats = Statistics::new();
        let mut applied = AppliedTxSet::default();
        let outcome =
            replay_count_deltas(&mut stats, &mut applied, batch.iter().map(|(t, d)| (*t, d)));
        (stats, applied, outcome)
    }

    /// **The replay's result does not depend on the order the records arrive in** (`rmp` #1066,
    /// acceptance criterion 2), proved by permuting the batch.
    ///
    /// Log order is not apply order — that is the whole reason this record exists — so a replay that
    /// depended on it would give a different durable answer on every recovery of the same log. The
    /// batch is chosen so that the property has teeth: `saturating_batch` contains a create and a
    /// later delete of the same label, and applying its deltas one at a time in the order
    /// `(3, 1, 2)` clamps `L` at `0` and then raises it to `1`, yielding a count of **1** for a label
    /// nothing carries. All six permutations are checked, and the expected value is computed from
    /// the arithmetic rather than from one of the runs.
    #[test]
    fn replay_is_independent_of_the_order_the_records_arrive_in() {
        let batch = saturating_batch();
        let permutations: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut results = Vec::new();
        for order in permutations {
            let permuted: Vec<(TxnId, CountDelta)> =
                order.iter().map(|&i| batch[i].clone()).collect();
            let (stats, applied, outcome) = replay(&permuted);
            assert_eq!(
                outcome.applied, 3,
                "order {order:?}: not every record landed"
            );
            assert_eq!(outcome.already_applied, 0);
            results.push((
                stats.total_nodes,
                stats.nodes_per_label.clone(),
                applied.clone(),
            ));
        }
        // The arithmetic: +1 +1 −1 nodes, and L nets to zero so it must be ABSENT (the zero-count
        // invariant), while M keeps its one node.
        let want_per_label: BTreeMap<u32, u64> = [(M, 1)].into_iter().collect();
        for (i, (total, per_label, applied)) in results.iter().enumerate() {
            assert_eq!(
                (*total, per_label),
                (1, &want_per_label),
                "permutation {i} ({:?}) produced a different catalogue: applying the deltas one at \
                 a time lets the saturating rail in Statistics::add_keyed swallow a decrement, so \
                 the sum has to be taken BEFORE anything is applied",
                permutations[i]
            );
            assert_eq!(
                *applied, results[0].2,
                "permutation {i} produced a different applied set"
            );
        }
        // NON-VACUITY, part 1: the batch really does expose the hazard. Walked one delta at a time in
        // the order that puts the delete first, an intermediate count for `L` goes NEGATIVE — which
        // is precisely the state `Statistics` cannot represent. Shadowed on an exact `i128` so this
        // is a statement about the batch and holds in every build profile.
        let mut shadow: i128 = 0;
        let mut went_negative = false;
        for i in [2usize, 0, 1] {
            batch[i].1.for_each(|key, d| {
                if key == CountKey::Label(L) {
                    shadow += i128::from(d);
                    went_negative |= shadow < 0;
                }
            });
        }
        assert_eq!(shadow, 0, "the shadow must end where the real fold ends");
        assert!(
            went_negative,
            "NON-VACUITY: the batch was supposed to drive a counter negative when applied one delta \
             at a time, and it did not — so the permutation assertion above proves nothing"
        );

        // NON-VACUITY, part 2: a counter driven negative does not come back. `Statistics` clamps at
        // zero, so the `−1` is LOST and the following `+1` lands on `0` instead of on `−1`. Which
        // way that shows up depends only on the build profile, and both are the same defect:
        // `debug_assert!` catches it in a debug build, and a release build takes the rail in silence
        // and serves the wrong number — the release behaviour being the one that ships, and the
        // reason `rmp` #1052's oracle is a value rather than a panic.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let clamped = std::panic::catch_unwind(|| {
            let mut s = Statistics::new();
            s.apply_count_delta(CountKey::Label(L), -1);
            s.apply_count_delta(CountKey::Label(L), 1);
            s.nodes_per_label.get(&L).copied()
        });
        std::panic::set_hook(hook);
        match clamped {
            Err(_) => { /* debug build: the rail is caught at the source, as designed */ }
            Ok(got) => assert_eq!(
                got,
                Some(1),
                "NON-VACUITY: a release build was supposed to clamp the negative intermediate at \
                 zero and come back with 1 where the truth is 0. It did not, so the saturating rail \
                 this whole design routes around does not exist and the fold is unnecessary"
            ),
        }
    }

    /// **A delta applied twice counts once** (`rmp` #1066, acceptance criterion 3).
    ///
    /// Two recoveries of the same log, with the applied set carried across as a checkpoint would
    /// carry it, must leave the counters where the first one did. The **positive control** is in the
    /// test: the same batch replayed against a *fresh* applied set — which is exactly what removing
    /// the set from the mechanism would produce — doubles the counters, and that is asserted, so a
    /// green run cannot mean "the batch had nothing to double".
    #[test]
    fn a_delta_replayed_twice_is_counted_once() {
        let batch: Vec<(TxnId, CountDelta)> = vec![
            (TxnId(1), delta(2, 0, &[(L, 2)], &[], &[], &[])),
            (
                TxnId(2),
                delta(1, 1, &[(M, 1)], &[(9, 1)], &[((M, 9), 1)], &[]),
            ),
        ];

        let mut stats = Statistics::new();
        let mut applied = AppliedTxSet::default();
        let first =
            replay_count_deltas(&mut stats, &mut applied, batch.iter().map(|(t, d)| (*t, d)));
        assert_eq!(first.applied, 2);
        let after_first = stats.clone();

        // Recovery number two, over the SAME log, with the applied set the checkpoint persisted.
        let second =
            replay_count_deltas(&mut stats, &mut applied, batch.iter().map(|(t, d)| (*t, d)));
        assert_eq!(
            (second.applied, second.already_applied),
            (0, 2),
            "the second replay admitted a record whose transaction is already in the applied set"
        );
        assert_eq!(
            stats, after_first,
            "replaying the same log twice moved the counters twice — `count()` is answered from \
             this number and nothing recomputes it at open, so the drift is permanent"
        );

        // Duplicates WITHIN one batch collapse the same way.
        let doubled: Vec<(TxnId, &CountDelta)> = batch
            .iter()
            .chain(batch.iter())
            .map(|(t, d)| (*t, d))
            .collect();
        let mut stats_dup = Statistics::new();
        let mut applied_dup = AppliedTxSet::default();
        let outcome = replay_count_deltas(&mut stats_dup, &mut applied_dup, doubled);
        assert_eq!((outcome.applied, outcome.already_applied), (2, 2));
        assert_eq!(stats_dup, after_first);

        // POSITIVE CONTROL: without the applied set, the second pass doubles everything. This is
        // what the mechanism buys, measured rather than assumed — if this assertion ever fails, the
        // one above is vacuous because there was nothing to prevent.
        let mut unguarded = Statistics::new();
        let mut throwaway = AppliedTxSet::default();
        replay_count_deltas(
            &mut unguarded,
            &mut throwaway,
            batch.iter().map(|(t, d)| (*t, d)),
        );
        let mut fresh_set = AppliedTxSet::default();
        replay_count_deltas(
            &mut unguarded,
            &mut fresh_set,
            batch.iter().map(|(t, d)| (*t, d)),
        );
        assert_eq!(
            unguarded.total_nodes,
            after_first.total_nodes * 2,
            "NON-VACUITY: replaying with a fresh applied set was supposed to double the counters \
             and did not, so the idempotence assertion above proves nothing"
        );
        assert_ne!(unguarded, after_first);
    }

    /// **A replay against a non-empty base neither saturates nor loses the base**, and the applied
    /// set decides membership per transaction rather than per batch.
    #[test]
    fn a_partially_applied_batch_folds_only_what_is_missing() {
        let base_batch: Vec<(TxnId, CountDelta)> = vec![
            (TxnId(4), delta(3, 0, &[(L, 3)], &[], &[], &[])),
            (TxnId(9), delta(2, 0, &[(M, 2)], &[], &[], &[])),
        ];
        let mut stats = Statistics::new();
        let mut applied = AppliedTxSet::default();
        replay_count_deltas(
            &mut stats,
            &mut applied,
            base_batch.iter().map(|(t, d)| (*t, d)),
        );
        assert_eq!(stats.total_nodes, 5);
        // 4 and 9 are applied; the frontier is still 0 because 1..=3 were never seen.
        assert_eq!(applied.frontier(), 0);
        assert_eq!(applied.stray().collect::<Vec<_>>(), vec![4, 9]);

        // A second recovery finds the same two records plus a third, and folds only the third.
        let mut wider = base_batch.clone();
        wider.push((TxnId(6), delta(-1, 0, &[(L, -1)], &[], &[], &[])));
        let outcome =
            replay_count_deltas(&mut stats, &mut applied, wider.iter().map(|(t, d)| (*t, d)));
        assert_eq!((outcome.applied, outcome.already_applied), (1, 2));
        assert_eq!(stats.total_nodes, 4);
        assert_eq!(stats.nodes_per_label.get(&L), Some(&2));
        assert_eq!(stats.nodes_per_label.get(&M), Some(&2));
        assert!(applied.contains(TxnId(6)));
    }

    /// **A record whose delta is empty still marks its transaction applied.**
    ///
    /// Otherwise a transaction that logged a delta which happens to net to nothing would be
    /// re-admitted on every recovery. Harmless for the counters, but it would keep the id out of the
    /// applied set for ever and stall the gap-free frontier just below it.
    #[test]
    fn an_empty_delta_still_marks_its_transaction_applied() {
        let empty = CountDelta::default();
        let mut stats = Statistics::new();
        let mut applied = AppliedTxSet::default();
        let outcome = replay_count_deltas(&mut stats, &mut applied, [(TxnId(1), &empty)]);
        assert_eq!(outcome.applied, 1);
        assert_eq!(stats, Statistics::new(), "an empty delta moved a counter");
        assert!(applied.contains(TxnId(1)));
        assert_eq!(applied.frontier(), 1);
    }

    /// **The live accumulator and the wire form are the same fact.**
    ///
    /// `CountDelta` is what a transaction accumulates through `record` *and* what it will log, so a
    /// delta built the way the write path builds one must survive the codec unchanged. This is the
    /// bridge `rmp` #1067 will cross: it logs the very object the active table already holds.
    #[test]
    fn a_delta_built_the_way_the_write_path_builds_one_round_trips() {
        let mut d = CountDelta::default();
        for _ in 0..3 {
            d.record(CountKey::TotalNodes, 1);
            d.record(CountKey::Label(L), 1);
        }
        d.record(CountKey::TotalNodes, -1);
        d.record(CountKey::Label(L), -1);
        d.record(CountKey::TotalRelationships, 1);
        d.record(CountKey::RelType(9), 1);
        d.record(CountKey::StartLabelType(L, 9), 1);
        d.record(CountKey::TypeEndLabel(9, L), 1);
        // A key that nets to zero is pruned by `record`, so it must not appear on the wire either.
        d.record(CountKey::Label(M), 1);
        d.record(CountKey::Label(M), -1);
        assert!(!d.is_empty());
        assert_eq!(CountDelta::decode(&d.encode()).expect("round-trip"), d);
        assert!(
            !d.per_label.contains_key(&M),
            "a key that netted to zero survived into the logged payload"
        );
        assert_eq!(d.per_label.get(&L), Some(&2));
    }
}
