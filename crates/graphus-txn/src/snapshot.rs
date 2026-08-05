//! Isolation levels, read snapshots, and the registry that resolves a writer's commit status.
//!
//! A [`Snapshot`] is a read timestamp plus the identity of its owning transaction (so a
//! transaction can always see its **own** uncommitted writes, `04 §5.3`). The [`IsolationLevel`]
//! selects whether the manager runs full SSI validation at commit.
//!
//! Resolving a version's visibility (`04 §5.3`) requires knowing, for any [`VersionStamp`], whether
//! the writer is committed (and at which timestamp) or aborted/in-flight. The frozen header stores
//! only the writer's `TxnId` while it is in flight; the mapping `TxnId → outcome` lives in the
//! [`CommitRegistry`], which is the manager's Active/Recent Transaction Table.

// FxHashMap: keyed by internal TxnId (never attacker-controlled) and never iterated in an
// order-observable way, so the faster non-cryptographic hash is safe on this visibility hot path.
use rustc_hash::FxHashMap as HashMap;

use graphus_core::{CommandId, Timestamp, TxnId};

use crate::oracle::VersionStamp;

/// The isolation level a transaction runs at (`D-isolation-level`).
///
/// Both levels read from a consistent MVCC snapshot (`04 §5.3`); they differ **only** at commit:
/// [`Serializable`](IsolationLevel::Serializable) runs SSI dangerous-structure validation and may
/// abort a pivot, whereas [`Snapshot`](IsolationLevel::Snapshot) does not and therefore permits
/// write-skew (`04 §5.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// **Default.** Full Serializable Snapshot Isolation: snapshot reads + SSI commit validation.
    #[default]
    Serializable,
    /// Documented weaker opt-in: plain Snapshot Isolation (no SSI validation). Permits write-skew.
    Snapshot,
}

impl IsolationLevel {
    /// Whether transactions at this level run SSI validation at commit.
    #[must_use]
    pub fn runs_ssi(self) -> bool {
        matches!(self, IsolationLevel::Serializable)
    }
}

/// Which side of the **current statement** a read is taken on (`04 §5.1.4`).
///
/// The snapshot timestamp settles what other transactions the reader sees; the view settles what it
/// sees of its **own** transaction, and it only ever matters for changes the reader's own current
/// command made. Memgraph carries the same two-valued distinction and for the same reason
/// (`/data/refsrc/memgraph/src/storage/v2/view.hpp`); PostgreSQL expresses it as `cmin`/`cmax`
/// against the snapshot's `curcid`.
///
/// The difference is one comparison operator in [`command_hides_own_write`]:
///
/// | View | An own delta written by command `c` is undone when |
/// | --- | --- |
/// | [`New`](View::New) | `c > current` — only a *later* command's write, which cannot exist |
/// | [`Old`](View::Old) | `c >= current` — including the current command's own writes |
///
/// with one carve-out either way: a delta written at [`CommandId::NONE`] — outside any statement,
/// by recovery, a maintenance pass or the catalog — belongs to the transaction's **baseline** rather
/// than to a statement, and is never undone by either view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// **Default.** Read-your-own-writes in full: everything this transaction has written, including
    /// the statement currently running. This is the polarity a write path owes (it must see what it
    /// has just written) and the one every read had before `rmp` #972.
    #[default]
    New,
    /// The state as it stood when the current statement started. This transaction's earlier
    /// statements are visible; the current statement's own writes are undone.
    ///
    /// This is the polarity that makes a statement immune to its own mutations — the Halloween
    /// problem — independently of whether the planner inserted an eagerness barrier.
    Old,
}

/// Whether a delta written by command `writer` of the reader's **own** transaction must be undone
/// for a read taken at command `current` under `view`.
///
/// This is the whole of statement-level isolation, factored out of the chain walk so that the rule
/// is stated once and tested directly. `Snapshot` handles it through
/// [`Snapshot::hides_own_command`].
#[must_use]
pub fn command_hides_own_write(view: View, writer: CommandId, current: CommandId) -> bool {
    // A write made outside any statement precedes every statement of its transaction by definition,
    // so no view undoes it. Without this carve-out an `OLD` read would erase the work of recovery, of
    // a maintenance pass, or of the catalog — none of which runs statements.
    if writer == CommandId::NONE {
        return false;
    }
    match view {
        // A later command's write is undone. Within one transaction that cannot normally arise —
        // statements run one at a time — but a `>` rather than a blanket `false` keeps the rule
        // total, so a future concurrent-statement path cannot read a command that has not run.
        View::New => writer > current,
        // The current command's own writes are undone as well: that is what OLD means.
        View::Old => writer >= current,
    }
}

/// A read snapshot: the begin timestamp, the owning transaction's identity, and the point **within**
/// that transaction the read is taken at.
///
/// Carrying the [`TxnId`] lets visibility honour the "a transaction sees its own uncommitted writes"
/// rule (`04 §5.3`) without a side lookup; carrying the [`CommandId`] and the [`View`] refines that
/// rule to statement granularity (`04 §5.1.4`), so a statement can be shown the state that preceded
/// it. A snapshot is [`Copy`] and 24 bytes, and is threaded by value through every read seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The transaction this snapshot belongs to.
    pub owner: TxnId,
    /// The begin timestamp `s`: a version's `xmin` must have committed `≤ s` to be visible.
    pub ts: Timestamp,
    /// The statement within [`owner`](Self::owner) this read is taken at (`04 §5.1.4`).
    pub command: CommandId,
    /// Which side of [`command`](Self::command) the read is taken on.
    pub view: View,
}

impl Snapshot {
    /// A snapshot for `owner` at `ts`, reading its own transaction's **first** statement under the
    /// [`View::New`] polarity — read-your-own-writes in full.
    ///
    /// This is the constructor for every caller that does not run statements: maintenance passes,
    /// recovery, the consistency checker, and tests that assert cross-transaction visibility. A
    /// statement-driven read builds its snapshot with [`at_command`](Self::at_command) instead.
    #[must_use]
    pub const fn new(owner: TxnId, ts: Timestamp) -> Self {
        Self {
            owner,
            ts,
            command: CommandId::FIRST,
            view: View::New,
        }
    }

    /// A snapshot pinned to one statement of `owner` and one side of it.
    #[must_use]
    pub const fn at_command(owner: TxnId, ts: Timestamp, command: CommandId, view: View) -> Self {
        Self {
            owner,
            ts,
            command,
            view,
        }
    }

    /// The same snapshot read on the other side of the same statement.
    #[must_use]
    pub const fn with_view(self, view: View) -> Self {
        Self { view, ..self }
    }

    /// The same snapshot advanced to `command`, keeping the view.
    #[must_use]
    pub const fn with_command(self, command: CommandId) -> Self {
        Self { command, ..self }
    }

    /// Whether a delta this snapshot's **own** transaction wrote at command `writer` must be undone.
    ///
    /// The caller must already have established that the delta belongs to [`owner`](Self::owner);
    /// this decides only the statement-granularity half of the question.
    #[must_use]
    pub fn hides_own_command(self, writer: CommandId) -> bool {
        debug_assert!(
            self.view == View::New || self.command != CommandId::NONE,
            "an OLD read must name the statement it is old relative to; reading OLD at \
             CommandId::NONE means the statement seam never called `begin_command`, which would \
             turn the whole guarantee into a silent no-op"
        );
        command_hides_own_write(self.view, writer, self.command)
    }
}

/// The committed/aborted outcome of a transaction (its Active/Recent Transaction Table entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnOutcome {
    /// Still running: no commit timestamp yet.
    InFlight,
    /// Committed at the given commit timestamp.
    Committed(Timestamp),
    /// Aborted; its writes are never visible to anyone.
    Aborted,
}

/// Resolves `TxnId → outcome` for in-flight, recently-committed, and aborted writers.
///
/// Visibility (`04 §5.3`) needs this to turn a header word's in-flight `TxnId` into a commit
/// timestamp (or to learn it aborted). Entries are kept until garbage collection proves no live
/// snapshot can still observe the transaction's effect; until then they must be retained so an
/// older reader resolves the writer correctly.
#[derive(Debug, Default, Clone)]
pub struct CommitRegistry {
    outcomes: HashMap<TxnId, TxnOutcome>,
}

impl CommitRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `txn` has started (now [`TxnOutcome::InFlight`]).
    pub fn register_begin(&mut self, txn: TxnId) {
        self.outcomes.insert(txn, TxnOutcome::InFlight);
    }

    /// Records that `txn` committed at `commit_ts`.
    pub fn record_commit(&mut self, txn: TxnId, commit_ts: Timestamp) {
        self.outcomes.insert(txn, TxnOutcome::Committed(commit_ts));
    }

    /// Records that `txn` aborted.
    pub fn record_abort(&mut self, txn: TxnId) {
        self.outcomes.insert(txn, TxnOutcome::Aborted);
    }

    /// Forgets `txn` once GC proves it is no longer observable. After this, the writer must not be
    /// referenced by any live version header.
    pub fn forget(&mut self, txn: TxnId) {
        self.outcomes.remove(&txn);
    }

    /// The number of entries currently in the table (observability: GC-time pruning, `04 §5.5`,
    /// bounds this; see [`prune_settled`](Self::prune_settled)).
    #[must_use]
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether the table holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// The writers currently recorded as [`TxnOutcome::Committed`], in no particular order.
    ///
    /// GC captures this set **after** its header-freeze sweep (`04 §5.5`, `rmp` task #59): the sweep
    /// rewrote every on-disk in-flight stamp of these writers to its committed timestamp, so once
    /// the freeze is durable (the GC transaction commits) every one of them may be
    /// [`forget`](Self::forget)-ten without any version becoming unresolvable.
    #[must_use]
    pub fn committed_writers(&self) -> Vec<TxnId> {
        self.outcomes
            .iter()
            .filter_map(|(txn, outcome)| match outcome {
                TxnOutcome::Committed(_) => Some(*txn),
                TxnOutcome::InFlight | TxnOutcome::Aborted => None,
            })
            .collect()
    }

    /// Prunes entries that GC has proven settled, returning how many were removed (`04 §5.5`,
    /// `rmp` task #59): every [`TxnOutcome::Aborted`] entry (an unknown id already resolves as
    /// aborted, so forgetting one is semantically a no-op) and every [`TxnOutcome::Committed`] entry
    /// whose commit timestamp is at or below `low_water` (`None` = no active transactions, so every
    /// committed entry is settled). [`TxnOutcome::InFlight`] entries are always kept.
    ///
    /// The caller must guarantee that no version header a reader can still consult carries a pruned
    /// writer's in-flight stamp — for the [`VersionedStore`](crate::store::VersionedStore) contract
    /// that holds at commit (`commit_writer` settles every stamp); for a lazy-freezing store it holds
    /// only after a durable GC freeze pass.
    pub fn prune_settled(&mut self, low_water: Option<Timestamp>) -> usize {
        let before = self.outcomes.len();
        self.outcomes.retain(|_, outcome| match outcome {
            TxnOutcome::InFlight => true,
            TxnOutcome::Aborted => false,
            TxnOutcome::Committed(ts) => low_water.is_some_and(|mark| *ts > mark),
        });
        before - self.outcomes.len()
    }

    /// The recorded outcome of `txn`. An unknown id is treated as [`TxnOutcome::Aborted`]: it was
    /// either never committed, or already GC'd because it is provably invisible — both mean its
    /// writes are not visible (`04 §5.3`).
    #[must_use]
    pub fn outcome(&self, txn: TxnId) -> TxnOutcome {
        self.outcomes
            .get(&txn)
            .copied()
            .unwrap_or(TxnOutcome::Aborted)
    }

    /// Resolves a raw header word into the committed timestamp of its writer, if any.
    ///
    /// Returns:
    /// - `Some(ts)` when the word is a committed timestamp, or an in-flight `TxnId` that the
    ///   registry has since recorded as committed at `ts`;
    /// - `None` when the word is the `0` sentinel, or names an in-flight or aborted writer.
    #[must_use]
    pub fn resolve_commit_ts(&self, word: u64) -> Option<Timestamp> {
        match VersionStamp::from_raw(word) {
            VersionStamp::None => None,
            VersionStamp::Committed(ts) => Some(ts),
            VersionStamp::InFlight(txn) => match self.outcome(txn) {
                TxnOutcome::Committed(ts) => Some(ts),
                TxnOutcome::InFlight | TxnOutcome::Aborted => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole of statement-level isolation is one comparison operator per view, so it is asserted
    /// directly rather than only through the storage paths that consume it (`04 §5.1.4`).
    #[test]
    fn the_view_decides_only_the_current_commands_own_writes() {
        let current = CommandId(5);
        for (view, earlier, same, later) in [
            (View::New, false, false, true),
            (View::Old, false, true, true),
        ] {
            assert_eq!(
                command_hides_own_write(view, CommandId(4), current),
                earlier,
                "{view:?}: an EARLIER command's own write is always already reflected"
            );
            assert_eq!(
                command_hides_own_write(view, current, current),
                same,
                "{view:?}: the CURRENT command's own write is the one the two views disagree about"
            );
            assert_eq!(
                command_hides_own_write(view, CommandId(6), current),
                later,
                "{view:?}: a LATER command's own write is never reflected"
            );
        }
    }

    /// `CommandId::NONE` is what a delta written outside any statement carries — recovery, a
    /// maintenance pass, the catalog. Such a write belongs to the transaction's baseline, so **no**
    /// view undoes it, at any command.
    ///
    /// Without the carve-out, `NONE >= NONE` makes a maintenance transaction's `OLD` read erase its
    /// own work — which is exactly what the storage-level scenario
    /// `command_isolation_972::a_statementless_write_survives_a_later_statements_old_view` caught.
    #[test]
    fn a_statementless_write_is_never_undone_by_any_view() {
        for current in [CommandId::NONE, CommandId::FIRST, CommandId(9)] {
            for view in [View::New, View::Old] {
                assert!(
                    !command_hides_own_write(view, CommandId::NONE, current),
                    "{view:?} at {current:?} must not undo a baseline write"
                );
            }
        }
        // The neighbouring real command is undone, so the carve-out is not swallowing the rule.
        assert!(command_hides_own_write(
            View::Old,
            CommandId::FIRST,
            CommandId::FIRST
        ));
    }

    /// A [`Snapshot`] is copied by value into every read on the hot path, so its size is a cost the
    /// engine pays per read and not an implementation detail. `rmp` #972 grew it from 16 bytes to 24
    /// by adding the command and the view; this pins that, so a later field cannot widen it silently.
    #[test]
    fn a_snapshot_is_three_words() {
        assert_eq!(size_of::<Snapshot>(), 24);
        // The command and the view fit in the padding a `(u64, u64)` already carried, so the growth
        // is one word rather than two.
        assert_eq!(align_of::<Snapshot>(), 8);
    }

    #[test]
    fn a_snapshot_defaults_to_the_first_command_under_the_new_view() {
        let s = Snapshot::new(TxnId(3), Timestamp(9));
        assert_eq!(s.command, CommandId::FIRST);
        assert_eq!(s.view, View::New);
        assert_eq!(s.with_view(View::Old).view, View::Old);
        assert_eq!(s.with_command(CommandId(7)).command, CommandId(7));
        // Neither derived form disturbs the parts that decide cross-transaction visibility.
        assert_eq!(s.with_view(View::Old).ts, s.ts);
        assert_eq!(s.with_command(CommandId(7)).owner, s.owner);
    }

    /// The counter is monotonic even at the ceiling: wrapping would make a later statement's own
    /// writes look older than its first, which is a visibility error rather than an overflow.
    #[test]
    fn the_command_counter_saturates_rather_than_wrapping() {
        assert_eq!(CommandId::FIRST.next(), CommandId(2));
        assert_eq!(CommandId(u32::MAX).next(), CommandId(u32::MAX));
    }

    #[test]
    fn levels_select_ssi_correctly() {
        assert!(IsolationLevel::default().runs_ssi());
        assert!(IsolationLevel::Serializable.runs_ssi());
        assert!(!IsolationLevel::Snapshot.runs_ssi());
    }

    #[test]
    fn unknown_writer_is_treated_as_aborted() {
        let reg = CommitRegistry::new();
        assert_eq!(reg.outcome(TxnId(9)), TxnOutcome::Aborted);
        assert_eq!(
            reg.resolve_commit_ts(VersionStamp::in_flight(TxnId(9))),
            None
        );
    }

    #[test]
    fn resolve_commit_ts_follows_outcome_transitions() {
        let mut reg = CommitRegistry::new();
        let word = VersionStamp::in_flight(TxnId(3));
        reg.register_begin(TxnId(3));
        assert_eq!(reg.resolve_commit_ts(word), None); // in flight
        reg.record_commit(TxnId(3), Timestamp(50));
        assert_eq!(reg.resolve_commit_ts(word), Some(Timestamp(50)));
        reg.record_abort(TxnId(3));
        assert_eq!(reg.resolve_commit_ts(word), None); // aborted
    }

    #[test]
    fn prune_settled_keeps_in_flight_and_unsettled_committed_entries() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(1)); // in flight: always kept
        reg.record_commit(TxnId(2), Timestamp(10)); // committed ≤ low_water: pruned
        reg.record_commit(TxnId(3), Timestamp(30)); // committed > low_water: kept
        reg.record_abort(TxnId(4)); // aborted: pruned (unknown resolves as aborted anyway)
        assert_eq!(reg.len(), 4);

        let mut committed = reg.committed_writers();
        committed.sort_unstable();
        assert_eq!(committed, vec![TxnId(2), TxnId(3)]);

        assert_eq!(reg.prune_settled(Some(Timestamp(20))), 2);
        assert_eq!(reg.outcome(TxnId(1)), TxnOutcome::InFlight);
        assert_eq!(reg.outcome(TxnId(2)), TxnOutcome::Aborted); // forgotten = unknown = aborted
        assert_eq!(reg.outcome(TxnId(3)), TxnOutcome::Committed(Timestamp(30)));
        assert_eq!(reg.len(), 2);

        // No active transactions: every committed entry is settled.
        assert_eq!(reg.prune_settled(None), 1);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        assert_eq!(reg.outcome(TxnId(1)), TxnOutcome::InFlight);
    }

    #[test]
    fn committed_word_resolves_without_registry_entry() {
        let reg = CommitRegistry::new();
        assert_eq!(
            reg.resolve_commit_ts(VersionStamp::committed(Timestamp(8))),
            Some(Timestamp(8))
        );
    }
}
