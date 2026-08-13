//! MVCC visibility — the exact `04 §5.3` rules over a record's frozen `xmin`/`xmax` header words —
//! and [`CommitOracle`], the **single door** through which every header stamp is resolved.
//!
//! A transaction `T` with snapshot `s` sees a version `v` **iff**:
//!
//! 1. `v.xmin` is committed with `commit_ts(xmin) ≤ s`, **and**
//! 2. `v.xmax` is `0`, **or** `v.xmax` is uncommitted, **or** `v.xmax` aborted, **or**
//!    `commit_ts(xmax) > s`.
//!
//! plus the override: a transaction always sees its **own** uncommitted writes (clause 1 is
//! satisfied when `xmin` names `T`'s own in-flight write), and an own-uncommitted `xmax` hides the
//! version from its own author too (a transaction does not see what it has itself deleted).
//!
//! The two header words are raw `u64`s. This module is **pure** — no mutation, no locking, no shared
//! state of its own — which is exactly why reads never block writers (`04 §5.7`, NFR-4). Since
//! `rmp` #1069 phase 3 the *oracle* it calls into does read a page, so a visibility decision is no
//! longer free; it is still lock-free with respect to writers, which is the property that matters
//! here, and it costs nothing at all once a version's stamp has been settled by GC.
//!
//! # The door (`rmp` #1069)
//!
//! Every question a caller may ask of a **header** stamp goes through [`CommitOracle`]:
//!
//! | Question | Method |
//! | --- | --- |
//! | What became of the transaction this word names? | [`resolve_stamp`](CommitOracle::resolve_stamp) |
//! | Which writer does this word name, whatever became of it? | [`names_writer`](CommitOracle::names_writer) |
//! | Does this word name **my own** write? | [`names_own_write`](CommitOracle::names_own_write) |
//! | Both of the two above, in **one** resolution | [`resolve_for`](CommitOracle::resolve_for) |
//! | At which timestamp did this word's transaction commit? | [`resolve_commit_ts`](CommitOracle::resolve_commit_ts) |
//! | Does this pair of words make the version visible to me? | [`is_visible_via`] |
//!
//! There is deliberately **no** free function that decides visibility from a [`CommitRegistry`]
//! directly: the former `graphus_txn::is_visible` was removed rather than deprecated, so a caller
//! cannot bypass the door by accident. That is a guarantee by types, not a `grep` convention.
//!
//! The door is **fallible** because resolving a stamp *is* a durable read: `rmp` #1069 phase 3
//! re-pointed `MvccHeader.created_ts`/`expired_ts` at the commit slot in `commit.store`, and a slot
//! read can fail. A caller must never answer an unresolvable stamp with a default — an existence
//! question that cannot be resolved fails the read (`rmp` #733).
//!
//! # ⚠ Two populations, two types — this door serves only ONE
//!
//! Two unrelated sets of `u64` words share one bit layout, and confusing them produces **wrong
//! visibility that compiles in silence**. Since `rmp` #1069 phase 3 each has its own type:
//!
//! - the **record header** — `MvccHeader.created_ts` / `expired_ts`, typed
//!   [`HeaderStamp`](graphus_core::HeaderStamp), payload a **commit slot id**. *This* is the
//!   population this door resolves.
//! - the **commit slot** — `graphus_storage::undo::CommitSlot.commit_ts`, typed
//!   [`VersionStamp`], payload a `TxnId`, now and for ever. It is resolved by
//!   `graphus_storage::scan_polarity::delta_verdict` and `open_writer_of`, which must **not** be
//!   routed through this door.
//!
//! The two types are the guard, and they are only a partial one: both decode any `u64` without
//! complaint, so passing a slot's `commit_ts` to [`resolve_stamp`](CommitOracle::resolve_stamp) is
//! still a type-correct, silently-wrong call. What the split buys is that every *intentional* use
//! names the population it means, so a mix-up is now a visible choice at the call site rather than
//! an invisible default.
//!
//! [`RegistryOracle`] is the one place where the header population is deliberately read with the
//! *old* convention — see its docs before using it.
//!
//! ## What this module deliberately cannot answer (`rmp` #972)
//!
//! The header records **which transaction** created or expired a version and never **which statement
//! of it**, because `05 §12.2` puts the `command_id` on the undo delta rather than in the live
//! record. So the "own uncommitted writes" override above is stated at *transaction* granularity, and
//! it is the strongest answer these two words support.
//!
//! Statement granularity — [`View::Old`](crate::View), the rule that stops a statement from
//! observing its own writes — is therefore resolved one layer down, against the entity's undo chain:
//! `graphus_storage::read_view::entity_visible_at` refines this predicate for exactly the case the
//! header cannot decide, and `graphus_storage::scan_polarity::delta_verdict` applies the same rule to
//! properties, labels and adjacency. A caller that needs the statement-granular answer must use those
//! seams; this function is the cross-transaction half, and is complete as such.

use graphus_core::{Result, Timestamp, TxnId};

use crate::oracle::VersionStamp;
use crate::snapshot::{CommitRegistry, Snapshot, TxnOutcome};

/// What a **header** stamp word resolves to (`04 §5.3`).
///
/// This is the door's answer type: a raw `u64` from `MvccHeader.created_ts` / `expired_ts`, decoded
/// *and* resolved against whichever oracle owns commit outcomes. It is deliberately **not**
/// [`VersionStamp`], which is only the on-disk encoding: `VersionStamp::InFlight(w)` says "this word
/// names writer `w`", whereas `StampOutcome` says what became of that writer.
///
/// See the module docs: this type describes the **record header** population of stamps, never
/// `CommitSlot.commit_ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampOutcome {
    /// The `0` sentinel: no creator recorded, or (for `expired_ts`) the version is live.
    None,
    /// The word's transaction committed at this timestamp.
    Committed(Timestamp),
    /// The word's transaction is recorded as still running.
    ///
    /// # Answerable since `rmp` #1069 phase 3 — but still not the liveness question
    ///
    /// A slot-backed oracle answers this **truthfully**: a `commit.store` slot that is in use and
    /// still carries its writer's in-flight stamp is a *durable* record of a transaction that
    /// neither committed nor aborted. Before phase 3 this arm was dead — [`CommitRegistry::outcome`]
    /// gains an entry only when a transaction **resolves** and maps an unknown id to
    /// [`TxnOutcome::Aborted`], so a running writer read as [`Aborted`](Self::Aborted). That is the
    /// documented root cause of `rmp` #522 and `rmp` #778, and it is why
    /// [`RegistryOracle`] still cannot produce this variant.
    ///
    /// **It is nevertheless not the "is this writer alive?" predicate.** A slot says the transaction
    /// *had not resolved when its slot was last written*; a crash leaves loser slots in exactly that
    /// state until recovery, and a transaction on another node of the same process is alive only if
    /// the Active Transaction Table says so. A gate whose subject is liveness — "keep covering this
    /// record because its writer may still commit" — must ask
    /// `graphus_storage::RecordStore::is_txn_active`, and combine it with the *identity*
    /// [`names_writer`](CommitOracle::names_writer) gives it. See
    /// `RecordStore::is_inflight_of_inflight_writer` for the worked reasoning.
    InFlight(TxnId),
    /// The word's transaction aborted, or is not known to the oracle at all — which means the same
    /// thing for visibility: its writes are never visible (`04 §5.3`).
    Aborted,
}

/// The single door through which a **record header** stamp word is resolved (`rmp` #1069).
///
/// Implemented by `graphus_storage::RecordStore` and `graphus_storage::StoreReadView`, which resolve
/// a header's [`HeaderStamp::Slot`](graphus_core::HeaderStamp::Slot) against the durable
/// `commit.store` — the single commit oracle since phase 3. [`RegistryOracle`] implements it over the
/// in-memory table for the two populations that still carry a `TxnId` payload.
///
/// Read the module docs before implementing or calling: this trait resolves **header** stamps only,
/// never `CommitSlot.commit_ts`.
pub trait CommitOracle {
    /// What became of the transaction that `word` names.
    ///
    /// # Errors
    /// A storage fault while resolving the stamp. Never answer such a fault with a default — an
    /// unresolvable stamp must fail the read closed (`rmp` #733).
    fn resolve_stamp(&self, word: u64) -> Result<StampOutcome>;

    /// The writer `word` names, if it names one at all — **regardless of that writer's outcome**.
    ///
    /// This is the identity question, and it is distinct from [`resolve_stamp`](Self::resolve_stamp)
    /// on purpose: a caller asking "is this word held by a writer that is still running?" must
    /// combine this with a live-writer predicate (`RecordStore::is_txn_active`), because
    /// [`StampOutcome::InFlight`] is dead through the registry (see its docs). Routing such a gate
    /// through `resolve_stamp` alone silently turns it into a no-op — `rmp` #522 / #778.
    ///
    /// Returns `None` for the `0` sentinel and for an already-frozen `Committed` word: neither names
    /// a writer any more.
    ///
    /// # Errors
    /// A storage fault while resolving the stamp.
    fn names_writer(&self, word: u64) -> Result<Option<TxnId>>;

    /// Whether `word` names `owner`'s **own** uncommitted write.
    ///
    /// This is the comparison the "a transaction always sees its own writes" override rests on
    /// (`04 §5.3`), and the reason it is a named method rather than an open-coded
    /// `word == VersionStamp::in_flight(owner)` at each call site: in phase 3 the header stops
    /// carrying a `TxnId`, and this rule must then change in exactly **one** place.
    ///
    /// # Errors
    /// A storage fault while resolving the stamp.
    fn names_own_write(&self, word: u64, owner: TxnId) -> Result<bool> {
        Ok(self.names_writer(word)? == Some(owner))
    }

    /// Both questions [`is_visible_via`] asks of one word, answered from **one** resolution
    /// (`rmp` #1069): what became of the transaction the word names, and whether that transaction is
    /// `owner` itself.
    ///
    /// The default composes the two methods above, which is exactly right for an oracle whose
    /// resolution is free. It exists to be **overridden** by one whose resolution is a durable read:
    /// asking the two questions separately reads the same commit slot twice per header word, i.e.
    /// four reads per record where one suffices. Callers should prefer this over the pair whenever
    /// they want both answers; a caller that wants only one still asks for only one.
    ///
    /// # Errors
    /// A storage fault while resolving the stamp. As everywhere on this door, never answered with a
    /// default (`rmp` #733).
    fn resolve_for(&self, word: u64, owner: TxnId) -> Result<(StampOutcome, bool)> {
        Ok((
            self.resolve_stamp(word)?,
            self.names_own_write(word, owner)?,
        ))
    }

    /// Debug-time cross-check hook: `self` has just decided that `(xmin, xmax)` is `verdict` for
    /// `snapshot` (`rmp` #1069 AC 2).
    ///
    /// The default does nothing, and an implementor that overrides it is expected to make the body
    /// `debug_assertions`-only so a release build optimises the call away entirely. It exists so the
    /// slot-backed oracle can compare its **verdict** — never its outcome — against the one the
    /// pre-#1069 [`CommitRegistry`] would have produced over the same records, on every read the
    /// whole DST battery performs, without a new test per scenario.
    ///
    /// Deliberately infallible and return-less: an audit that could fail the read would be a second
    /// oracle in the answer path, which is the very thing `rmp` #1069 removes. It diverges loudly or
    /// it says nothing.
    fn audit_visibility(&self, _snapshot: Snapshot, _xmin: u64, _xmax: u64, _verdict: bool) {}

    /// The commit timestamp of the transaction `word` names, if it has one.
    ///
    /// Returns:
    /// - `Some(ts)` when the word resolves to a committed transaction (whether the word is already
    ///   frozen to `Committed(ts)` or still names a writer the oracle has since recorded as
    ///   committed at `ts`);
    /// - `None` for the `0` sentinel, and for an in-flight or aborted (or unknown) transaction.
    ///
    /// # Errors
    /// A storage fault while resolving the stamp.
    fn resolve_commit_ts(&self, word: u64) -> Result<Option<Timestamp>> {
        Ok(match self.resolve_stamp(word)? {
            StampOutcome::Committed(ts) => Some(ts),
            StampOutcome::None | StampOutcome::InFlight(_) | StampOutcome::Aborted => None,
        })
    }
}

/// The in-memory Active/Recent Transaction Table as a [`CommitOracle`], for the words whose payload
/// really is a [`TxnId`].
///
/// # ⚠ This is NOT the record-header oracle any more (`rmp` #1069 phase 3)
///
/// `impl CommitOracle for CommitRegistry` was **removed**, not renamed, and this wrapper is not a
/// restoration of it. The difference is the whole point of the phase: a bare
/// `registry.resolve_stamp(w)` compiled everywhere and read a record header — whose payload is now a
/// `commit.store` slot id — as though the payload were a transaction id. Naming the wrapper makes
/// every remaining use of the old convention a deliberate, greppable, reviewable act. A record
/// header must be resolved by the store (`graphus_storage::RecordStore` /
/// `graphus_storage::StoreReadView`), never here.
///
/// There are exactly two legitimate uses:
///
/// 1. **Populations that still carry a `TxnId`.** The in-memory reference store
///    (`crate::store::MemVersionedStore`) stamps its own headers with
///    [`VersionStamp::in_flight`](crate::oracle::VersionStamp::in_flight) and resolves them here; it
///    has no `commit.store` and never touches a record header.
/// 2. **The `rmp` #1069 AC 2 equivalence audit.** The slot-backed oracle reconstructs, byte for
///    byte, the word the pre-phase-3 build would have written and checks that this oracle reaches
///    the same *verdict* — see [`CommitOracle::audit_visibility`].
///
/// Infallible: every method wraps its answer in `Ok`, because the table is a `HashMap` in this
/// process. It therefore cannot produce [`StampOutcome::InFlight`] (see that variant's docs).
#[derive(Debug, Clone, Copy)]
pub struct RegistryOracle<'a>(pub &'a CommitRegistry);

impl CommitOracle for RegistryOracle<'_> {
    fn resolve_stamp(&self, word: u64) -> Result<StampOutcome> {
        Ok(match VersionStamp::from_raw(word) {
            VersionStamp::None => StampOutcome::None,
            VersionStamp::Committed(ts) => StampOutcome::Committed(ts),
            // An unknown id maps to `Aborted` here exactly as `outcome` documents: it either never
            // committed, or GC already forgot it because it is provably invisible. Both mean "not
            // visible". This is also why `StampOutcome::InFlight` is unreachable through this impl.
            VersionStamp::InFlight(txn) => match self.0.outcome(txn) {
                TxnOutcome::Committed(ts) => StampOutcome::Committed(ts),
                TxnOutcome::InFlight => StampOutcome::InFlight(txn),
                TxnOutcome::Aborted => StampOutcome::Aborted,
            },
        })
    }

    fn names_writer(&self, word: u64) -> Result<Option<TxnId>> {
        // Decoded, never resolved: the identity of the writer is in the word itself, and asking the
        // table about it would collapse a running writer into `Aborted` (see `StampOutcome::InFlight`).
        Ok(match VersionStamp::from_raw(word) {
            VersionStamp::InFlight(txn) => Some(txn),
            VersionStamp::None | VersionStamp::Committed(_) => None,
        })
    }
}

/// Whether `T` (via `snapshot`) sees the version whose header carries `xmin` and `xmax`.
///
/// `xmin` is the raw `created_ts` word; `xmax` is the raw `expired_ts` word
/// (`graphus_storage::record::MvccHeader`). `oracle` resolves both.
///
/// Implements `04 §5.3` to the letter; see the module docs for the clause breakdown. This replaced
/// the former infallible `graphus_txn::is_visible`, which was **removed** so that no caller can
/// decide visibility without going through the door (`rmp` #1069).
///
/// # Errors
/// Propagates an oracle fault. The caller must fail the read closed on it (`rmp` #733) — never
/// substitute a default verdict, which is precisely the answer the door exists to prevent.
pub fn is_visible_via(
    oracle: &impl CommitOracle,
    snapshot: Snapshot,
    xmin: u64,
    xmax: u64,
) -> Result<bool> {
    // Short-circuited exactly as the former `creator_visible(..) && !expirer_hides(..)` was: an
    // invisible creator never asks the oracle about the expirer.
    let verdict = if creator_visible(oracle, snapshot, xmin)? {
        !expirer_hides(oracle, snapshot, xmax)?
    } else {
        false
    };
    // The `rmp` #1069 AC 2 cross-check, on EVERY visibility decision the engine makes. A no-op
    // unless the oracle overrides it, and overridden only under `debug_assertions`.
    oracle.audit_visibility(snapshot, xmin, xmax, verdict);
    Ok(verdict)
}

/// Clause 1: is the version's **creator** visible to `snapshot`?
///
/// True when `xmin` names the snapshot owner's own in-flight write, or resolves to a committed write
/// at `commit_ts ≤ s`. An in-flight write by *another* transaction, an aborted creator, or the `0`
/// sentinel is not visible.
fn creator_visible(oracle: &impl CommitOracle, snapshot: Snapshot, xmin: u64) -> Result<bool> {
    // ONE resolution, both answers (`rmp` #1069): against a slot-backed oracle the pair
    // `names_own_write` + `resolve_stamp` would read the same commit slot twice.
    let (outcome, own) = oracle.resolve_for(xmin, snapshot.owner)?;
    // Own uncommitted write: always visible to its author, and tested FIRST because an oracle has no
    // settled answer for a writer that has not resolved yet.
    if own {
        return Ok(true);
    }
    Ok(match outcome {
        StampOutcome::Committed(ts) => ts <= snapshot.ts,
        StampOutcome::None | StampOutcome::InFlight(_) | StampOutcome::Aborted => false,
    })
}

/// Clause 2 (negated): does the version's **expirer** hide it from `snapshot`?
///
/// A version is hidden when `xmax` resolves to a committed deletion at `commit_ts ≤ s`, or names the
/// snapshot owner's *own* uncommitted deletion. It is **not** hidden when `xmax` is `0`, names
/// another in-flight writer, names an aborted writer, or committed at `commit_ts > s`.
fn expirer_hides(oracle: &impl CommitOracle, snapshot: Snapshot, xmax: u64) -> Result<bool> {
    // ONE resolution, both answers — see `creator_visible`.
    let (outcome, own) = oracle.resolve_for(xmax, snapshot.owner)?;
    // We deleted it ourselves in this transaction: we no longer see it.
    if own {
        return Ok(true);
    }
    Ok(match outcome {
        StampOutcome::Committed(ts) => ts <= snapshot.ts,
        // Live, uncommitted or aborted: does not hide the version.
        StampOutcome::None | StampOutcome::InFlight(_) | StampOutcome::Aborted => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::VersionStamp;
    use graphus_core::{Timestamp, TxnId};

    fn snap(owner: u64, ts: u64) -> Snapshot {
        Snapshot::new(TxnId(owner), Timestamp(ts))
    }

    fn committed(ts: u64) -> u64 {
        VersionStamp::committed(Timestamp(ts))
    }

    fn inflight(txn: u64) -> u64 {
        VersionStamp::in_flight(TxnId(txn))
    }

    /// The former free function's shape, so every assertion below is unchanged from the pre-#1069
    /// suite: only the plumbing (`?` on an infallible oracle) is new.
    fn is_visible(snapshot: Snapshot, xmin: u64, xmax: u64, reg: &CommitRegistry) -> bool {
        is_visible_via(&RegistryOracle(reg), snapshot, xmin, xmax)
            .expect("the in-memory registry never faults")
    }

    // ---- Clause 1: creator visibility ----

    #[test]
    fn creator_committed_before_snapshot_is_visible() {
        let reg = CommitRegistry::new();
        // xmin committed at 5, snapshot at 10, live (xmax = 0) -> visible.
        assert!(is_visible(snap(1, 10), committed(5), 0, &reg));
    }

    #[test]
    fn creator_committed_after_snapshot_is_invisible() {
        let reg = CommitRegistry::new();
        // xmin committed at 15 > snapshot 10 -> invisible (we predate it).
        assert!(!is_visible(snap(1, 10), committed(15), 0, &reg));
    }

    #[test]
    fn creator_committed_exactly_at_snapshot_is_visible() {
        let reg = CommitRegistry::new();
        // `commit_ts(xmin) ≤ s` is inclusive.
        assert!(is_visible(snap(1, 10), committed(10), 0, &reg));
    }

    #[test]
    fn another_in_flight_creator_is_invisible() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(2));
        // xmin is txn 2's in-flight write; reader is txn 1 -> invisible.
        assert!(!is_visible(snap(1, 10), inflight(2), 0, &reg));
    }

    #[test]
    fn aborted_creator_is_invisible() {
        let mut reg = CommitRegistry::new();
        reg.record_abort(TxnId(2));
        assert!(!is_visible(snap(1, 10), inflight(2), 0, &reg));
    }

    #[test]
    fn own_uncommitted_write_is_visible() {
        let reg = CommitRegistry::new();
        // xmin is the reader's own in-flight write -> always visible, even with no registry entry.
        assert!(is_visible(snap(7, 10), inflight(7), 0, &reg));
    }

    // ---- Clause 2: expirer (xmax) ----

    #[test]
    fn live_version_xmax_zero_is_visible() {
        let reg = CommitRegistry::new();
        assert!(is_visible(snap(1, 10), committed(5), 0, &reg));
    }

    #[test]
    fn expired_before_snapshot_is_invisible() {
        let reg = CommitRegistry::new();
        // Created at 5, deleted (committed) at 8, snapshot at 10 -> deletion is visible -> hidden.
        assert!(!is_visible(snap(1, 10), committed(5), committed(8), &reg));
    }

    #[test]
    fn expired_after_snapshot_is_still_visible() {
        let reg = CommitRegistry::new();
        // Concurrent xmax committed at 12 > snapshot 10 -> we still see the pre-deletion version.
        assert!(is_visible(snap(1, 10), committed(5), committed(12), &reg));
    }

    #[test]
    fn concurrent_uncommitted_xmax_does_not_hide() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(2));
        // Another txn has an uncommitted deletion -> the version is still visible to us.
        assert!(is_visible(snap(1, 10), committed(5), inflight(2), &reg));
    }

    #[test]
    fn aborted_xmax_does_not_hide() {
        let mut reg = CommitRegistry::new();
        reg.record_abort(TxnId(2));
        assert!(is_visible(snap(1, 10), committed(5), inflight(2), &reg));
    }

    #[test]
    fn own_uncommitted_deletion_hides_from_self() {
        let reg = CommitRegistry::new();
        // We created it earlier (committed at 5) and deleted it in this same txn (id 7) -> we no
        // longer see it.
        assert!(!is_visible(snap(7, 10), committed(5), inflight(7), &reg));
    }

    #[test]
    fn own_create_and_own_delete_is_invisible_to_self() {
        let reg = CommitRegistry::new();
        // Created and deleted within the same uncommitted txn -> gone for its author.
        assert!(!is_visible(snap(7, 10), inflight(7), inflight(7), &reg));
    }

    #[test]
    fn another_committed_xmax_resolved_via_registry() {
        let mut reg = CommitRegistry::new();
        // The header still holds the writer's TxnId, but it has since committed at 8.
        reg.record_commit(TxnId(2), Timestamp(8));
        assert!(!is_visible(snap(1, 10), committed(5), inflight(2), &reg));
        // ... and if that commit were after our snapshot we would still see the version.
        let mut reg2 = CommitRegistry::new();
        reg2.record_commit(TxnId(2), Timestamp(12));
        assert!(is_visible(snap(1, 10), committed(5), inflight(2), &reg2));
    }

    // ---- The door itself (`rmp` #1069) ----

    /// `resolve_stamp` must reproduce the pre-#1069 registry semantics word for word, including the
    /// rule that an **unknown** writer resolves as aborted (the arm `snapshot.rs` documented).
    #[test]
    fn resolve_stamp_reproduces_the_registry_semantics() {
        let mut reg = CommitRegistry::new();
        reg.record_commit(TxnId(2), Timestamp(8));
        reg.record_abort(TxnId(3));
        reg.register_begin(TxnId(4));

        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(0).unwrap(),
            StampOutcome::None
        );
        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(committed(5)).unwrap(),
            StampOutcome::Committed(Timestamp(5)),
            "an already-frozen word resolves without consulting the table at all"
        );
        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(inflight(2)).unwrap(),
            StampOutcome::Committed(Timestamp(8)),
            "a lazily-settled commit resolves through the table"
        );
        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(inflight(3)).unwrap(),
            StampOutcome::Aborted
        );
        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(inflight(9)).unwrap(),
            StampOutcome::Aborted,
            "an UNKNOWN writer resolves as aborted — the rule snapshot.rs:outcome documents"
        );
        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(inflight(4)).unwrap(),
            StampOutcome::InFlight(TxnId(4)),
            "only an explicitly registered begin ever reaches the InFlight arm"
        );
    }

    /// The dead-`InFlight` class, pinned rather than repaired (`rmp` #522 / #778): a writer that has
    /// merely BEGUN — the state every live writer is in, since the store's own
    /// Active-Transaction-Table is the thing that records it — resolves as `Aborted` here.
    ///
    /// This asserts the CURRENT semantics on purpose. A caller that needs "is this writer running?"
    /// must ask `RecordStore::is_txn_active`, never this door.
    #[test]
    fn a_writer_the_registry_never_saw_resolves_as_aborted_not_in_flight() {
        let reg = CommitRegistry::new();
        assert_eq!(
            RegistryOracle(&reg).resolve_stamp(inflight(42)).unwrap(),
            StampOutcome::Aborted
        );
        assert_ne!(
            RegistryOracle(&reg).resolve_stamp(inflight(42)).unwrap(),
            StampOutcome::InFlight(TxnId(42))
        );
    }

    /// `names_writer` answers the IDENTITY question and must NOT collapse a running writer into
    /// `Aborted` — that is the whole reason it is separate from `resolve_stamp`.
    #[test]
    fn names_writer_is_identity_not_outcome() {
        let mut reg = CommitRegistry::new();
        reg.record_commit(TxnId(2), Timestamp(8));
        reg.record_abort(TxnId(3));

        assert_eq!(RegistryOracle(&reg).names_writer(0).unwrap(), None);
        assert_eq!(
            RegistryOracle(&reg).names_writer(committed(5)).unwrap(),
            None
        );
        // Committed and aborted alike: the word still NAMES its writer.
        assert_eq!(
            RegistryOracle(&reg).names_writer(inflight(2)).unwrap(),
            Some(TxnId(2))
        );
        assert_eq!(
            RegistryOracle(&reg).names_writer(inflight(3)).unwrap(),
            Some(TxnId(3))
        );
        // And a writer nobody has ever heard of.
        assert_eq!(
            RegistryOracle(&reg).names_writer(inflight(99)).unwrap(),
            Some(TxnId(99))
        );
    }

    /// `names_own_write` is exactly the former open-coded
    /// `VersionStamp::from_raw(word) == VersionStamp::InFlight(owner)`.
    #[test]
    fn names_own_write_matches_the_open_coded_comparison() {
        let reg = CommitRegistry::new();
        for word in [0, committed(5), inflight(7), inflight(8)] {
            for owner in [TxnId(7), TxnId(8)] {
                assert_eq!(
                    RegistryOracle(&reg).names_own_write(word, owner).unwrap(),
                    VersionStamp::from_raw(word) == VersionStamp::InFlight(owner),
                    "word {word:#018x} vs owner {owner:?}"
                );
            }
        }
    }

    /// `resolve_commit_ts` keeps the exact contract it had as an inherent `CommitRegistry` method.
    #[test]
    fn resolve_commit_ts_follows_the_door() {
        let mut reg = CommitRegistry::new();
        assert_eq!(RegistryOracle(&reg).resolve_commit_ts(0).unwrap(), None);
        assert_eq!(
            RegistryOracle(&reg)
                .resolve_commit_ts(committed(8))
                .unwrap(),
            Some(Timestamp(8))
        );
        assert_eq!(
            RegistryOracle(&reg).resolve_commit_ts(inflight(9)).unwrap(),
            None
        );
        reg.record_commit(TxnId(9), Timestamp(50));
        assert_eq!(
            RegistryOracle(&reg).resolve_commit_ts(inflight(9)).unwrap(),
            Some(Timestamp(50))
        );
    }
}
