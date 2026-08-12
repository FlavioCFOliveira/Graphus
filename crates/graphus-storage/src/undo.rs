//! The undo area — the frozen on-disk form of the MVCC version chain
//! (`05-storage-format.md` §12, `04-technical-design.md` §5.1).
//!
//! Two fixed-record stores make up the area, framed exactly like the three record stores that
//! precede them (`05 §9`): [`UNDO_RECORD_SIZE`]-byte **deltas** in `undo.store`, and
//! [`COMMIT_RECORD_SIZE`]-byte **commit-info slots** in `commit.store`. Physical id `0` is the
//! reserved null pointer in both, so a chain terminates on `0` and a never-written slot — which is
//! all-zero — decodes as no delta at all (action `0` is not a valid action).
//!
//! ## A delta names the UNDO, not the redo
//!
//! This is the single convention a reader is most likely to get backwards, so it is stated here as
//! well as in the specification: **creating an entity writes a [`DeleteObject`](UndoAction::DeleteObject)
//! delta**, because deleting the entity is what undoes the creation. Every action in
//! [`UndoAction`] is named for the operation that *restores the previous state*, and the
//! "written when" column of `05 §12.3` is therefore the inverse of the action's name. Memgraph
//! names its own actions the same way and for the same reason
//! (`/data/refsrc/memgraph/src/storage/v2/delta_action.hpp:17-33`).
//!
//! ## The commit indirection point
//!
//! A delta carries **no timestamp of its own**. It carries the physical id of a
//! [`CommitSlot`] shared by every delta of its writing transaction, and that slot is published by a
//! single store at commit (`04 §5.1.3`). One write therefore commits every delta of a transaction
//! at the same instant: a reader resolves a delta's commit status by loading through the slot
//! rather than by reading a stamp the committer had to write into each record.
//!
//! ### The freeze sweep still runs — the two mechanisms coexist
//!
//! The indirection removes the need for a **delta** to carry a settled stamp. It did **not** retire
//! the per-record freeze sweep, which settles the in-place MVCC headers of the three record stores:
//! `RecordStore::freeze_store_headers_incremental` still walks `[freeze_low, high_water)` on every
//! GC pass, and the `freeze_low` frontier is still lowered whenever a fresh in-flight stamp lands
//! below it — by `note_created` / `note_expired`, and by the in-place property-cell write, which
//! re-stamps an id the sweep would otherwise never revisit. Both mechanisms are live in the current
//! code, and any reasoning about this store must account for both.
//!
//! Retiring the sweep is its own work, not a side effect of this indirection: `rmp` #1069 → #1070 →
//! #1071, in that order.
//!
//! ## Encoding
//!
//! All multi-byte integers are little-endian (`01-needs-survey.md` FR-ST-11). [`UndoDelta::encode`]
//! and [`UndoDelta::decode`] are exact inverses, and so are [`CommitSlot::encode`] /
//! [`CommitSlot::decode`] (round-trip tested below). Both decoders are **strict**: an unknown action
//! byte, a non-zero reserved byte, or a payload field set on an action that does not own it is
//! rejected rather than silently ignored, so a corrupt or forged image fails closed instead of
//! decoding into a plausible-looking delta.

use graphus_core::{GraphusError, Result};

/// Size of one delta record in `undo.store`, in bytes (`05 §12.1`).
///
/// Not a coincidence: Memgraph holds its own `Delta` to the same budget
/// (`static_assert(sizeof(Delta) <= 56, ...)`, `/data/refsrc/memgraph/src/storage/v2/delta.hpp:408`).
pub const UNDO_RECORD_SIZE: usize = 56;

/// Size of one commit-info slot in `commit.store`, in bytes (`05 §12.1`).
pub const COMMIT_RECORD_SIZE: usize = 32;

/// Delta / slot flag bit: the record is occupied (`05 §12.2`, `§12.4`). Shares the meaning — and the
/// bit position — of [`crate::record::FLAG_IN_USE`], so a slot's liveness is read the same way
/// everywhere in the store.
pub const FLAG_IN_USE: u8 = crate::record::FLAG_IN_USE;

/// The `type_tag` value that means **"no value here"** (`05 §12.2`; ratified decision
/// `D-property-removal`, `02-decision-register.md`).
///
/// It has one meaning and two readings, which are the same statement seen from the two ends of a
/// property's history:
///
/// * on a [`UndoAction::SetProperty`] delta — *the key was **absent** before the write this delta
///   undoes*, so undoing it removes the key rather than restoring a value;
/// * in a `props.store` cell — *this cell is **empty***: it keeps its `in_use` bit and its place in
///   the owner's `first_prop` chain (so the chain stays walkable and a later `SET` of the same key
///   reuses it with no allocation), but it holds no value and the key reads as absent.
///
/// **Nothing else can produce this tag**, which is what makes it usable as a sentinel rather than as
/// a value that merely happens to be unused today: the inline codec's tags start at `1`
/// ([`crate::propenc::TAG_BOOL`]) and the overflow codec's class tags start at `4`
/// ([`crate::valenc::TAG_STRING`]), always OR-ed with [`crate::valenc::OVERFLOW_BIT`]. The test
/// `no_encoder_can_emit_the_absent_type_tag` below pins that over both codecs' full tag sets.
///
/// One near-collision is worth naming, because a reader grepping for a zero tag will find it:
/// `valenc`'s private `TAG_LIST_EMPTY = 0` is an **element** tag *inside* an overflow payload's
/// bytes (it says "this list's elements have no type because the list is empty"). It is never a
/// record's or a delta's `type_tag`, and it is unreachable from here — a `List` value's record tag
/// is always `TAG_LIST | OVERFLOW_BIT`.
pub const TYPE_TAG_ABSENT: u8 = 0;

// --- delta field offsets (`05 §12.2`) ---
const D_OFF_FLAGS: usize = 0; // u8
const D_OFF_ACTION: usize = 1; // u8
const D_OFF_TYPE_TAG: usize = 2; // u8
const D_OFF_DIRECTION: usize = 3; // u8
const D_OFF_COMMAND_ID: usize = 4; // u32
const D_OFF_COMMIT_INFO: usize = 8; // u64
const D_OFF_NEXT: usize = 16; // u64
const D_OFF_TOKEN: usize = 24; // u32
const D_OFF_RESERVED: usize = 28; // u32, must be zero
const D_OFF_VALUE_INLINE: usize = 32; // u64
const D_OFF_PEER: usize = 40; // u64
const D_OFF_EDGE: usize = 48; // u64

// --- commit-slot field offsets (`05 §12.4`) ---
const C_OFF_FLAGS: usize = 0; // u8
const C_OFF_RESERVED: usize = 1; // 7 bytes, must be zero
const C_OFF_COMMIT_TS: usize = 8; // u64
const C_OFF_TXN_ID: usize = 16; // u64
const C_OFF_DELTA_COUNT: usize = 24; // u64

/// Byte offset of a delta's `flags` byte within its record. Exposed so the store can revert **only**
/// this byte when an aborting transaction's delta is undone, leaving the body (and with it `next`)
/// intact so a survivor that prepended on top still threads through the dead delta to its successor
/// — the same corpse discipline the relationship store uses (`rmp` #220).
pub const UNDO_OFF_FLAGS: usize = D_OFF_FLAGS;

/// Byte offset of a delta's `next` word — the chain link. Exposed so the publication protocol can
/// re-point a still-unpublished delta at a freshly re-read chain head when a compare-and-publish is
/// refused (`rmp` #1028): an entry whose `next` names a head that is no longer the head must never be
/// published, or the chain forks and everything below the winner falls out of it.
pub const UNDO_OFF_NEXT: usize = D_OFF_NEXT;

/// Byte offset of a commit slot's `flags` byte within its record. Same corpse discipline as
/// [`UNDO_OFF_FLAGS`]: an aborted transaction's slot keeps its `txn_id` and its in-flight
/// `commit_ts`, so the slot itself records "this transaction did not commit".
pub const COMMIT_OFF_FLAGS: usize = C_OFF_FLAGS;

/// Byte offset of a commit slot's `commit_ts` word — **the commit indirection point** (`05 §12.4`).
/// Published by a single store at commit, and the **last** of the two commit writes.
pub const COMMIT_OFF_COMMIT_TS: usize = C_OFF_COMMIT_TS;

/// Byte offset of a commit slot's `delta_count` word. Written **before** `commit_ts` at commit
/// (`05 §12.4`, normative ordering) and decremented by GC as each delta is reclaimed.
pub const COMMIT_OFF_DELTA_COUNT: usize = C_OFF_DELTA_COUNT;

/// The seven delta actions (`05 §12.3`, `04 §5.1.1`).
///
/// The discriminants are the frozen wire encoding, so a stored delta is decodable by any build that
/// reads this format version. Value `0` is reserved and is not a valid action, which is what makes a
/// zeroed (never-written or reclaimed) slot fail to decode as a delta.
///
/// **Each name is the action that UNDOES the change**, not the change itself — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum UndoAction {
    /// Restores the entity's non-existence. Written when a transaction **creates** a node or
    /// relationship.
    DeleteObject = 1,
    /// Restores the entity's existence. Written when a transaction **deletes** a node or
    /// relationship.
    RecreateObject = 2,
    /// Restores one property's previous value (or its previous absence, encoded as a `NULL`
    /// old value). Written when a transaction sets, changes, or removes a property. Uses `token`,
    /// `type_tag` and `value_inline`.
    SetProperty = 3,
    /// Restores a label's membership. Written when a transaction **removes** a label. Uses `token`.
    AddLabel = 4,
    /// Restores a label's absence. Written when a transaction **adds** a label. Uses `token`.
    RemoveLabel = 5,
    /// Restores one incidence entry. Written when a transaction **removes** an incident
    /// relationship from a node. Uses `token`, `direction`, `peer` and `edge`.
    AddIncidentEdge = 6,
    /// Restores the absence of one incidence entry. Written when a transaction **adds** an incident
    /// relationship to a node. Uses `token`, `direction`, `peer` and `edge`.
    RemoveIncidentEdge = 7,
}

impl UndoAction {
    /// The frozen single-byte wire discriminant (`05 §12.3`).
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decodes the frozen wire discriminant, or [`None`] for `0` (the reserved "not a delta" value)
    /// and for any unknown byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::DeleteObject),
            2 => Some(Self::RecreateObject),
            3 => Some(Self::SetProperty),
            4 => Some(Self::AddLabel),
            5 => Some(Self::RemoveLabel),
            6 => Some(Self::AddIncidentEdge),
            7 => Some(Self::RemoveIncidentEdge),
            _ => None,
        }
    }

    /// Whether this action owns the `token` / `type_tag` / `value_inline` property payload.
    #[must_use]
    pub const fn is_property(self) -> bool {
        matches!(self, Self::SetProperty)
    }

    /// Whether this action owns the `token` label payload.
    #[must_use]
    pub const fn is_label(self) -> bool {
        matches!(self, Self::AddLabel | Self::RemoveLabel)
    }

    /// Whether this action owns the `token` / `direction` / `peer` / `edge` incidence payload.
    #[must_use]
    pub const fn is_incidence(self) -> bool {
        matches!(self, Self::AddIncidentEdge | Self::RemoveIncidentEdge)
    }
}

/// Which end of a relationship the delta's entity is, for the two incidence actions (`05 §12.2`,
/// the `direction` byte). `0` for every other action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum IncidentDirection {
    /// The entity is the relationship's **start** node.
    Start = 1,
    /// The entity is the relationship's **end** node.
    End = 2,
}

impl IncidentDirection {
    /// The frozen single-byte wire discriminant.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decodes the frozen wire discriminant, or [`None`] for `0` (absent) and any unknown byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Start),
            2 => Some(Self::End),
            _ => None,
        }
    }
}

/// One delta: the immutable, fixed-size inverse of one change to one entity (`05 §12.2`).
///
/// A delta is **immutable once linked** (`04 §5.1.2` step 3): after its `next` is set and the
/// entity's `undo_ptr` is published, no field of it is ever rewritten. Only its slot is reused, and
/// only after GC has reclaimed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndoDelta {
    /// Flag bits ([`FLAG_IN_USE`], rest reserved and must be zero).
    pub flags: u8,
    /// Which change this delta undoes.
    pub action: UndoAction,
    /// [`UndoAction::SetProperty`] only: the old value's type tag, encoded exactly as
    /// `props.store`'s `type_tag` (`05 §9`), including its inline-vs-overflow bit. Zero otherwise.
    pub type_tag: u8,
    /// The two incidence actions only: `1` = start node, `2` = end node (see
    /// [`IncidentDirection`]). Zero otherwise.
    pub direction: u8,
    /// The statement counter within the writing transaction (`04 §5.1.4`) — a
    /// [`graphus_core::CommandId`] as a raw `u32`, stamped by
    /// `RecordStore::link_delta` from the transaction's own counter and **never** by the caller.
    ///
    /// It is what makes a statement isolated from itself: a read on
    /// [`View::Old`](graphus_txn::View::Old) undoes every delta of the current statement, so a
    /// statement cannot observe the rows it is itself producing (`rmp` #972). `0`
    /// ([`CommandId::NONE`](graphus_core::CommandId::NONE)) means the delta was written outside any
    /// statement — recovery, a maintenance pass, the catalog — and belongs to the transaction's
    /// baseline, which no view undoes.
    pub command_id: u32,
    /// Physical id in `commit.store` of the writing transaction's slot. Never `0` on a live delta.
    pub commit_info: u64,
    /// Physical id in `undo.store` of the next-older delta on this entity's chain; `0` = end.
    pub next: u64,
    /// `SetProperty`: the property-key token. `AddLabel`/`RemoveLabel`: the label token. The two
    /// incidence actions: the relationship-type token. Zero otherwise.
    pub token: u32,
    /// `SetProperty` only: the **old** value if it fits inline, else the `strings.store` block id,
    /// encoded exactly as `props.store`'s `value_inline` (`05 §9`). Zero otherwise.
    pub value_inline: u64,
    /// The two incidence actions only: physical id of the relationship's other endpoint node.
    /// Zero otherwise.
    pub peer: u64,
    /// The two incidence actions only: physical id of the relationship record. Zero otherwise.
    pub edge: u64,
}

impl UndoDelta {
    /// A live delta with only the common fields set: the action, its transaction's commit slot, the
    /// statement counter, and the chain link. Payload-carrying actions set their own fields on the
    /// returned value.
    #[must_use]
    pub fn new(action: UndoAction, commit_info: u64, command_id: u32, next: u64) -> Self {
        Self {
            flags: FLAG_IN_USE,
            action,
            type_tag: 0,
            direction: 0,
            command_id,
            commit_info,
            next,
            token: 0,
            value_inline: 0,
            peer: 0,
            edge: 0,
        }
    }

    /// Whether the [`FLAG_IN_USE`] bit is set. A decoded delta whose bit is **clear** is a *corpse*:
    /// an aborting transaction's delta whose creation undo cleared the flag while preserving the
    /// body, so a chain walk still threads through it to `next` but never applies its action.
    #[must_use]
    pub const fn in_use(self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    /// Encodes this delta into exactly [`UNDO_RECORD_SIZE`] bytes.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`UNDO_RECORD_SIZE`].
    pub fn encode(self, buf: &mut [u8]) {
        assert!(
            buf.len() >= UNDO_RECORD_SIZE,
            "undo delta buffer must be at least {UNDO_RECORD_SIZE} bytes"
        );
        buf[..UNDO_RECORD_SIZE].fill(0);
        buf[D_OFF_FLAGS] = self.flags;
        buf[D_OFF_ACTION] = self.action.as_byte();
        buf[D_OFF_TYPE_TAG] = self.type_tag;
        buf[D_OFF_DIRECTION] = self.direction;
        write_u32(buf, D_OFF_COMMAND_ID, self.command_id);
        write_u64(buf, D_OFF_COMMIT_INFO, self.commit_info);
        write_u64(buf, D_OFF_NEXT, self.next);
        write_u32(buf, D_OFF_TOKEN, self.token);
        write_u64(buf, D_OFF_VALUE_INLINE, self.value_inline);
        write_u64(buf, D_OFF_PEER, self.peer);
        write_u64(buf, D_OFF_EDGE, self.edge);
    }

    /// Decodes a delta from a record slot.
    ///
    /// Strict by design (see the module docs): a zeroed slot, an unknown action, a non-zero reserved
    /// word, an out-of-domain `direction`, or a payload field set on an action that does not own it
    /// is an error rather than a silently-tolerated value. Callers that want to distinguish "free
    /// slot" from "corrupt slot" test [`is_zeroed`] first.
    ///
    /// # Errors
    /// Returns a storage error describing exactly which invariant the slot violates.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`UNDO_RECORD_SIZE`].
    pub fn decode(buf: &[u8]) -> Result<Self> {
        assert!(
            buf.len() >= UNDO_RECORD_SIZE,
            "undo delta buffer must be at least {UNDO_RECORD_SIZE} bytes"
        );
        let flags = buf[D_OFF_FLAGS];
        if flags & !FLAG_IN_USE != 0 {
            return Err(GraphusError::Storage(format!(
                "undo delta has reserved flag bits set (flags {flags:#04x})"
            )));
        }
        let action_byte = buf[D_OFF_ACTION];
        let Some(action) = UndoAction::from_byte(action_byte) else {
            return Err(GraphusError::Storage(format!(
                "undo delta has an invalid action byte {action_byte}"
            )));
        };
        let reserved = read_u32(buf, D_OFF_RESERVED);
        if reserved != 0 {
            return Err(GraphusError::Storage(format!(
                "undo delta has a non-zero reserved word ({reserved})"
            )));
        }
        let delta = Self {
            flags,
            action,
            type_tag: buf[D_OFF_TYPE_TAG],
            direction: buf[D_OFF_DIRECTION],
            command_id: read_u32(buf, D_OFF_COMMAND_ID),
            commit_info: read_u64(buf, D_OFF_COMMIT_INFO),
            next: read_u64(buf, D_OFF_NEXT),
            token: read_u32(buf, D_OFF_TOKEN),
            value_inline: read_u64(buf, D_OFF_VALUE_INLINE),
            peer: read_u64(buf, D_OFF_PEER),
            edge: read_u64(buf, D_OFF_EDGE),
        };
        delta.validate_payload()?;
        Ok(delta)
    }

    /// Rejects any payload field that the decoded action does not own (`05 §12.2`: every such field
    /// is "zero for every other action"). Keeping this exact means a future build can tell a real
    /// payload from a stale one without consulting the writer's intent.
    fn validate_payload(&self) -> Result<()> {
        let bad = |field: &str| {
            Err(GraphusError::Storage(format!(
                "undo delta action {:?} must not set `{field}`",
                self.action
            )))
        };
        if !self.action.is_property() && (self.type_tag != 0 || self.value_inline != 0) {
            return bad("type_tag/value_inline");
        }
        if !self.action.is_incidence() && (self.direction != 0 || self.peer != 0 || self.edge != 0)
        {
            return bad("direction/peer/edge");
        }
        if self.action.is_incidence() && IncidentDirection::from_byte(self.direction).is_none() {
            return Err(GraphusError::Storage(format!(
                "undo delta action {:?} has an invalid direction byte {}",
                self.action, self.direction
            )));
        }
        if !(self.action.is_property() || self.action.is_label() || self.action.is_incidence())
            && self.token != 0
        {
            return bad("token");
        }
        Ok(())
    }
}

/// One commit-info slot: the commit indirection point of one writing transaction (`05 §12.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitSlot {
    /// Flag bits ([`FLAG_IN_USE`], rest reserved and must be zero).
    pub flags: u8,
    /// The writer's `TxnId` in the in-flight [`VersionStamp`](graphus_core::VersionStamp) encoding
    /// while the transaction is open, and its commit timestamp once it has committed. Written
    /// exactly once, by a single store, at commit — this is the commit indirection point.
    pub commit_ts: u64,
    /// The owning transaction's id, retained after commit for recovery and diagnostics.
    pub txn_id: u64,
    /// `0` while the transaction is open; the number of deltas the transaction created once it has
    /// committed, decremented by GC as each one is reclaimed.
    pub delta_count: u64,
}

impl CommitSlot {
    /// A freshly-opened slot for `txn`, carrying its in-flight stamp and no delta count.
    #[must_use]
    pub fn open(txn_id: u64, in_flight_stamp: u64) -> Self {
        Self {
            flags: FLAG_IN_USE,
            commit_ts: in_flight_stamp,
            txn_id,
            delta_count: 0,
        }
    }

    /// Whether the [`FLAG_IN_USE`] bit is set. A decoded slot whose bit is **clear** is a *corpse*:
    /// an aborted transaction's slot, kept (body intact) so a delta that survived as a corpse can
    /// still be attributed to the transaction that failed to commit.
    #[must_use]
    pub const fn in_use(self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    /// Encodes this slot into exactly [`COMMIT_RECORD_SIZE`] bytes.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`COMMIT_RECORD_SIZE`].
    pub fn encode(self, buf: &mut [u8]) {
        assert!(
            buf.len() >= COMMIT_RECORD_SIZE,
            "commit slot buffer must be at least {COMMIT_RECORD_SIZE} bytes"
        );
        buf[..COMMIT_RECORD_SIZE].fill(0);
        buf[C_OFF_FLAGS] = self.flags;
        write_u64(buf, C_OFF_COMMIT_TS, self.commit_ts);
        write_u64(buf, C_OFF_TXN_ID, self.txn_id);
        write_u64(buf, C_OFF_DELTA_COUNT, self.delta_count);
    }

    /// Decodes a commit slot from a record slot. Strict, exactly as [`UndoDelta::decode`] is.
    ///
    /// # Errors
    /// Returns a storage error if a reserved bit or byte is non-zero, or if the slot is zeroed
    /// (a zeroed slot is not a slot — `commit_ts` is never `0` on a real one, because a writer's
    /// in-flight stamp always has the in-flight bit set).
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`COMMIT_RECORD_SIZE`].
    pub fn decode(buf: &[u8]) -> Result<Self> {
        assert!(
            buf.len() >= COMMIT_RECORD_SIZE,
            "commit slot buffer must be at least {COMMIT_RECORD_SIZE} bytes"
        );
        let flags = buf[C_OFF_FLAGS];
        if flags & !FLAG_IN_USE != 0 {
            return Err(GraphusError::Storage(format!(
                "commit slot has reserved flag bits set (flags {flags:#04x})"
            )));
        }
        if buf[C_OFF_RESERVED..C_OFF_RESERVED + 7]
            .iter()
            .any(|&b| b != 0)
        {
            return Err(GraphusError::Storage(
                "commit slot has non-zero reserved bytes".to_owned(),
            ));
        }
        let commit_ts = read_u64(buf, C_OFF_COMMIT_TS);
        let txn_id = read_u64(buf, C_OFF_TXN_ID);
        if commit_ts == 0 || txn_id == 0 {
            return Err(GraphusError::Storage(format!(
                "commit slot is not a slot (commit_ts {commit_ts}, txn_id {txn_id})"
            )));
        }
        Ok(Self {
            flags,
            commit_ts,
            txn_id,
            delta_count: read_u64(buf, C_OFF_DELTA_COUNT),
        })
    }
}

/// Whether a record slot is entirely zero — a never-written or reclaimed slot, which is **not** a
/// decodable delta or commit slot (`05 §12.3`: action `0` is reserved). Used to tell "free" from
/// "corrupt" before calling a strict decoder.
#[must_use]
pub fn is_zeroed(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().expect("4-byte slice"))
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().expect("8-byte slice"))
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two record sizes are frozen by `05 §12.1`, together with the records-per-page counts they
    /// imply. A change to either silently re-addresses every stored delta, so both are asserted.
    #[test]
    fn record_sizes_and_page_density_match_the_frozen_format() {
        assert_eq!(UNDO_RECORD_SIZE, 56);
        assert_eq!(COMMIT_RECORD_SIZE, 32);
        assert_eq!(crate::paging::records_per_page(UNDO_RECORD_SIZE), 145);
        assert_eq!(crate::paging::records_per_page(COMMIT_RECORD_SIZE), 255);
    }

    #[test]
    fn action_bytes_are_the_frozen_encoding() {
        for (byte, action) in [
            (1u8, UndoAction::DeleteObject),
            (2, UndoAction::RecreateObject),
            (3, UndoAction::SetProperty),
            (4, UndoAction::AddLabel),
            (5, UndoAction::RemoveLabel),
            (6, UndoAction::AddIncidentEdge),
            (7, UndoAction::RemoveIncidentEdge),
        ] {
            assert_eq!(action.as_byte(), byte);
            assert_eq!(UndoAction::from_byte(byte), Some(action));
        }
        assert_eq!(UndoAction::from_byte(0), None, "0 is reserved");
        assert_eq!(UndoAction::from_byte(8), None);
        assert_eq!(UndoAction::from_byte(255), None);
    }

    /// A zeroed slot must never decode as a delta — the property that lets a fresh page and a
    /// reclaimed slot be told apart from a live one without any side table.
    #[test]
    fn a_zeroed_slot_is_not_a_delta() {
        let buf = [0u8; UNDO_RECORD_SIZE];
        assert!(is_zeroed(&buf));
        assert!(UndoDelta::decode(&buf).is_err());
        let buf = [0u8; COMMIT_RECORD_SIZE];
        assert!(is_zeroed(&buf));
        assert!(CommitSlot::decode(&buf).is_err());
    }

    fn sample_deltas() -> Vec<UndoDelta> {
        let mut prop = UndoDelta::new(UndoAction::SetProperty, 7, 3, 42);
        prop.token = 11;
        prop.type_tag = 0x83;
        prop.value_inline = 0xDEAD_BEEF_CAFE_F00D;
        let mut label = UndoDelta::new(UndoAction::RemoveLabel, 7, 4, 43);
        label.token = 62;
        let mut inc = UndoDelta::new(UndoAction::AddIncidentEdge, 7, 5, 44);
        inc.token = 9;
        inc.direction = IncidentDirection::End.as_byte();
        inc.peer = 1234;
        inc.edge = 5678;
        vec![
            UndoDelta::new(UndoAction::DeleteObject, 1, 0, 0),
            UndoDelta::new(UndoAction::RecreateObject, u64::MAX, u32::MAX, u64::MAX),
            prop,
            label,
            inc,
        ]
    }

    #[test]
    fn delta_round_trips_every_action() {
        for delta in sample_deltas() {
            let mut buf = [0xAAu8; UNDO_RECORD_SIZE];
            delta.encode(&mut buf);
            assert_eq!(UndoDelta::decode(&buf).expect("decodes"), delta);
        }
    }

    /// Encoding must fill the whole record: a re-used buffer may not leak bytes of the delta that
    /// previously occupied the slot into the reserved regions of the new one.
    #[test]
    fn encode_zeroes_every_byte_it_does_not_own() {
        let mut buf = [0xFFu8; UNDO_RECORD_SIZE];
        UndoDelta::new(UndoAction::DeleteObject, 1, 0, 0).encode(&mut buf);
        assert_eq!(read_u32(&buf, D_OFF_RESERVED), 0);
        assert_eq!(buf[D_OFF_TYPE_TAG], 0);
        assert_eq!(buf[D_OFF_DIRECTION], 0);
        assert_eq!(read_u64(&buf, D_OFF_PEER), 0);
        assert_eq!(read_u64(&buf, D_OFF_EDGE), 0);
    }

    #[test]
    fn decode_rejects_a_payload_field_its_action_does_not_own() {
        let mut buf = [0u8; UNDO_RECORD_SIZE];
        UndoDelta::new(UndoAction::DeleteObject, 1, 0, 0).encode(&mut buf);
        let mut forged = buf;
        write_u64(&mut forged, D_OFF_PEER, 9);
        assert!(UndoDelta::decode(&forged).is_err(), "peer on DeleteObject");
        let mut forged = buf;
        forged[D_OFF_TYPE_TAG] = 1;
        assert!(
            UndoDelta::decode(&forged).is_err(),
            "type_tag on DeleteObject"
        );
        let mut forged = buf;
        write_u32(&mut forged, D_OFF_TOKEN, 5);
        assert!(UndoDelta::decode(&forged).is_err(), "token on DeleteObject");
        let mut forged = buf;
        write_u32(&mut forged, D_OFF_RESERVED, 1);
        assert!(UndoDelta::decode(&forged).is_err(), "reserved word");
        let mut forged = buf;
        forged[D_OFF_FLAGS] = 0b0000_0010;
        assert!(UndoDelta::decode(&forged).is_err(), "reserved flag bit");
    }

    #[test]
    fn decode_rejects_an_incidence_delta_without_a_direction() {
        let mut inc = UndoDelta::new(UndoAction::AddIncidentEdge, 1, 0, 0);
        inc.direction = 0;
        let mut buf = [0u8; UNDO_RECORD_SIZE];
        inc.encode(&mut buf);
        assert!(UndoDelta::decode(&buf).is_err());
        buf[D_OFF_DIRECTION] = 3;
        assert!(UndoDelta::decode(&buf).is_err());
    }

    /// A corpse delta — the flag cleared, the body preserved — must still decode, because a chain
    /// walk has to read its `next` to thread through it (`rmp` #220 corpse discipline).
    #[test]
    fn a_corpse_delta_still_decodes_and_keeps_its_link() {
        let mut delta = UndoDelta::new(UndoAction::DeleteObject, 7, 1, 99);
        let mut buf = [0u8; UNDO_RECORD_SIZE];
        delta.encode(&mut buf);
        buf[D_OFF_FLAGS] = 0; // exactly what the creation undo writes back
        let decoded = UndoDelta::decode(&buf).expect("corpse decodes");
        assert!(!decoded.in_use());
        assert_eq!(decoded.next, 99);
        assert_eq!(decoded.commit_info, 7);
        delta.flags = 0;
        assert_eq!(decoded, delta);
    }

    /// [`TYPE_TAG_ABSENT`] is only a sentinel if **no encoder can emit it**. Both value codecs are
    /// swept over their complete tag surface: the inline codec through its public API (every
    /// inline-representable `Value` class), and the overflow codec through every class tag it
    /// defines, each OR-ed with the overflow bit exactly as the property write path stores it.
    ///
    /// If a future codec claims tag `0`, an empty cell and a removal delta would both become
    /// indistinguishable from a real value and every removal would silently read back as that
    /// value. This test is the gate.
    #[test]
    fn no_encoder_can_emit_the_absent_type_tag() {
        use graphus_core::Value;

        // The inline codec: every class it accepts, plus the boundary values of each.
        for v in [
            Value::Boolean(false),
            Value::Boolean(true),
            Value::Integer(0),
            Value::Integer(i64::MIN),
            Value::Integer(i64::MAX),
            Value::Float(0.0),
            Value::Float(f64::MIN),
            Value::Float(f64::MAX),
        ] {
            let (tag, _) = crate::propenc::encode_inline(&v).expect("inline-encodable");
            assert_ne!(
                tag, TYPE_TAG_ABSENT,
                "the inline codec emitted the absent sentinel for {v:?}"
            );
        }

        // The overflow codec: every class tag it defines, stored as the record/delta `type_tag`.
        for class_tag in [
            crate::valenc::TAG_STRING,
            crate::valenc::TAG_LIST,
            crate::valenc::TAG_DATE,
            crate::valenc::TAG_LOCAL_TIME,
            crate::valenc::TAG_ZONED_TIME,
            crate::valenc::TAG_LOCAL_DATE_TIME,
            crate::valenc::TAG_ZONED_DATE_TIME,
            crate::valenc::TAG_DURATION,
            crate::valenc::TAG_POINT,
            crate::valenc::TAG_DATE_WIDE,
        ] {
            assert_ne!(class_tag, TYPE_TAG_ABSENT, "class tag {class_tag} is zero");
            assert_ne!(
                class_tag | crate::valenc::OVERFLOW_BIT,
                TYPE_TAG_ABSENT,
                "stored overflow tag for class {class_tag} is the absent sentinel"
            );
        }
    }

    /// The "was absent" / "is empty" delta — `SetProperty` with a zero `type_tag` and a zero
    /// `value_inline` — must survive the strict decoder. It carries a real `token`, so it is not a
    /// zeroed slot, and its zero payload is exactly what says "there was no value here".
    #[test]
    fn an_absent_value_set_property_delta_round_trips() {
        let mut d = UndoDelta::new(UndoAction::SetProperty, 3, 0, 0);
        d.token = 77;
        d.type_tag = TYPE_TAG_ABSENT;
        d.value_inline = 0;
        let mut buf = [0u8; UNDO_RECORD_SIZE];
        d.encode(&mut buf);
        assert!(!is_zeroed(&buf), "a real delta is never a zeroed slot");
        let got = UndoDelta::decode(&buf).expect("the absent-value delta decodes");
        assert_eq!(got, d);
        assert_eq!(got.type_tag, TYPE_TAG_ABSENT);
        assert_eq!(got.value_inline, 0);
    }

    #[test]
    fn commit_slot_round_trips() {
        let slot = CommitSlot {
            flags: FLAG_IN_USE,
            commit_ts: 0x8000_0000_0000_002A,
            txn_id: 42,
            delta_count: 3,
        };
        let mut buf = [0x5Au8; COMMIT_RECORD_SIZE];
        slot.encode(&mut buf);
        assert_eq!(CommitSlot::decode(&buf).expect("decodes"), slot);
    }

    #[test]
    fn commit_slot_decode_rejects_forged_reserved_bytes() {
        let slot = CommitSlot::open(42, 0x8000_0000_0000_002A);
        let mut buf = [0u8; COMMIT_RECORD_SIZE];
        slot.encode(&mut buf);
        assert!(CommitSlot::decode(&buf).is_ok());
        let mut forged = buf;
        forged[C_OFF_RESERVED + 3] = 1;
        assert!(CommitSlot::decode(&forged).is_err());
        let mut forged = buf;
        forged[C_OFF_FLAGS] = 0b1000_0000;
        assert!(CommitSlot::decode(&forged).is_err());
    }
}
