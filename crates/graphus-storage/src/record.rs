//! Frozen on-disk record layouts and their codecs (`05-storage-format.md` §7,
//! `04-technical-design.md` §2.3).
//!
//! Every node, relationship, and property record begins with the **25-byte MVCC record
//! header** frozen in `05 §7`, so the transaction manager can apply visibility uniformly.
//! Type-specific fields are appended after that prefix; their exact packing is frozen here and
//! mirrored in the integration tests.
//!
//! All multi-byte integers are little-endian (`01-needs-survey.md` FR-ST-11). Decoding from a
//! page slice and encoding back are exact inverses (round-trip tested below).
//!
//! ## Physical id 0 is the null pointer
//!
//! Field offsets that hold a *physical record id* (`first_rel`, `first_prop`, `next_prop`, the
//! relationship chain pointers, `undo_ptr`) use `0` to mean "none". Real records are therefore
//! allocated starting at id `1` (`04 §2.2`); see [`crate::store`].

use graphus_core::ElementId;

/// Size of the frozen MVCC record header in bytes (`05 §7`).
pub const MVCC_HEADER_SIZE: usize = 25;

/// MVCC header flag bit: the record slot is occupied (`05 §7`).
pub const FLAG_IN_USE: u8 = 0b0000_0001;
/// MVCC header flag bit: the node is *dense* (`05 §7`; `04 §2.5`). Reserved for the dense-node
/// promotion path, which is a follow-up task — this codec stores and round-trips the bit.
pub const FLAG_DENSE: u8 = 0b0000_0010;

// --- MVCC header field offsets (within any record) ---
const OFF_FLAGS: usize = 0; // u8
const OFF_CREATED_TS: usize = 1; // u64
const OFF_EXPIRED_TS: usize = 9; // u64
const OFF_UNDO_PTR: usize = 17; // u64

/// Byte offset of the `created_ts` (`xmin`) word within any record's MVCC header (`05 §7`). Exposed
/// so the store can settle just this 8-byte word at commit (freeze `xmin` to a committed timestamp)
/// without rewriting the whole record.
pub const MVCC_OFF_CREATED_TS: usize = OFF_CREATED_TS;
/// Byte offset of the `expired_ts` (`xmax`) word within any record's MVCC header (`05 §7`). Exposed
/// so the store can stamp an MVCC tombstone (`xmax`) or settle it at commit with an 8-byte patch.
pub const MVCC_OFF_EXPIRED_TS: usize = OFF_EXPIRED_TS;

/// The frozen MVCC record header shared by every node, relationship and property record
/// (`05 §7`).
///
/// `created_ts` holds the creating transaction's commit [`Timestamp`](graphus_core::Timestamp)
/// once committed, or the writer's [`TxnId`](graphus_core::TxnId) while uncommitted (the
/// [`VersionStamp`](graphus_core::VersionStamp) convention); `expired_ts` is `0` while the version
/// is live, or carries the deleting transaction's stamp once tombstoned; `undo_ptr` is the physical
/// id of the older version (`0` = none, reserved for the per-value version chain, a follow-up). The
/// store is **MVCC-native** (`rmp` task #45): it stamps `xmin` in-flight on create, settles it to
/// the commit timestamp at commit, MVCC-tombstones `xmax` on delete, and reclaims tombstones by GC;
/// `graphus-txn`'s visibility rule reads these words directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MvccHeader {
    /// Flag bits ([`FLAG_IN_USE`], [`FLAG_DENSE`], rest reserved).
    pub flags: u8,
    /// Creating transaction's commit timestamp, or its `TxnId` while uncommitted.
    pub created_ts: u64,
    /// Expiring transaction's commit timestamp; `0` = live (latest visible version).
    pub expired_ts: u64,
    /// Physical id of the older version (undo chain head); `0` = none.
    pub undo_ptr: u64,
}

impl MvccHeader {
    /// A live, in-use header created by transaction-or-timestamp `created_ts`.
    #[must_use]
    pub fn live(created_ts: u64) -> Self {
        Self {
            flags: FLAG_IN_USE,
            created_ts,
            expired_ts: 0,
            undo_ptr: 0,
        }
    }

    /// Whether the [`FLAG_IN_USE`] bit is set.
    #[must_use]
    pub fn in_use(self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    /// Whether the [`FLAG_DENSE`] bit is set.
    #[must_use]
    pub fn dense(self) -> bool {
        self.flags & FLAG_DENSE != 0
    }

    pub(crate) fn read(buf: &[u8]) -> Self {
        Self {
            flags: buf[OFF_FLAGS],
            created_ts: read_u64(buf, OFF_CREATED_TS),
            expired_ts: read_u64(buf, OFF_EXPIRED_TS),
            undo_ptr: read_u64(buf, OFF_UNDO_PTR),
        }
    }

    pub(crate) fn write(self, buf: &mut [u8]) {
        buf[OFF_FLAGS] = self.flags;
        write_u64(buf, OFF_CREATED_TS, self.created_ts);
        write_u64(buf, OFF_EXPIRED_TS, self.expired_ts);
        write_u64(buf, OFF_UNDO_PTR, self.undo_ptr);
    }
}

// =============================== Node record ===============================

/// Size of a node record in bytes (`04 §2.3`): MVCC header + `element_id` + `first_rel` +
/// `first_prop` + `labels`.
pub const NODE_RECORD_SIZE: usize = 65;

const NODE_OFF_ELEMENT_ID: usize = 25; // u128
/// Byte offset of the `first_rel` chain-head pointer within a node record (used by the store's
/// compare-and-set chain-head logical undo).
pub(crate) const NODE_OFF_FIRST_REL: usize = 41; // u64
/// Byte offset of the `first_prop` chain-head pointer within a node record (used by the store's
/// compare-and-set chain-head logical undo).
pub(crate) const NODE_OFF_FIRST_PROP: usize = 49; // u64
const NODE_OFF_LABELS: usize = 57; // u64

/// A node record (`04 §2.3`): the head of this node's relationship incidence chain
/// (`first_rel`) and property chain (`first_prop`), plus a packed `labels` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRecord {
    /// The frozen MVCC prefix.
    pub mvcc: MvccHeader,
    /// Stable, never-reused public identity (`D-element-id`).
    pub element_id: ElementId,
    /// Physical id of the first relationship incident to this node (`0` = no incident edges).
    pub first_rel: u64,
    /// Physical id of the first property in this node's chain (`0` = none).
    pub first_prop: u64,
    /// Inline label-set reference: small sets bit-packed, large sets a token-list block id
    /// (`04 §2.3`). Round-tripped opaquely by this codec.
    pub labels: u64,
}

impl NodeRecord {
    /// A fresh, live, in-use node with the given identity and no edges/properties.
    #[must_use]
    pub fn new(element_id: ElementId, created_ts: u64) -> Self {
        Self {
            mvcc: MvccHeader::live(created_ts),
            element_id,
            first_rel: 0,
            first_prop: 0,
            labels: 0,
        }
    }

    /// Decodes a node record from a [`NODE_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`NODE_RECORD_SIZE`].
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        assert!(buf.len() >= NODE_RECORD_SIZE, "node record slice too short");
        Self {
            mvcc: MvccHeader::read(buf),
            element_id: ElementId(read_u128(buf, NODE_OFF_ELEMENT_ID)),
            first_rel: read_u64(buf, NODE_OFF_FIRST_REL),
            first_prop: read_u64(buf, NODE_OFF_FIRST_PROP),
            labels: read_u64(buf, NODE_OFF_LABELS),
        }
    }

    /// Encodes this node record into a [`NODE_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`NODE_RECORD_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= NODE_RECORD_SIZE, "node record slice too short");
        self.mvcc.write(buf);
        write_u128(buf, NODE_OFF_ELEMENT_ID, self.element_id.0);
        write_u64(buf, NODE_OFF_FIRST_REL, self.first_rel);
        write_u64(buf, NODE_OFF_FIRST_PROP, self.first_prop);
        write_u64(buf, NODE_OFF_LABELS, self.labels);
    }
}

// =========================== Relationship record ===========================

/// Size of a relationship record in bytes (`04 §2.3`): MVCC header + `element_id` + `type` +
/// `start_node` + `end_node` + the four incidence-chain pointers + `first_prop` + `chain_flags`.
pub const REL_RECORD_SIZE: usize = 102;

const REL_OFF_ELEMENT_ID: usize = 25; // u128
const REL_OFF_TYPE: usize = 41; // u32
const REL_OFF_START_NODE: usize = 45; // u64
const REL_OFF_END_NODE: usize = 53; // u64
/// Byte offset of the `start_prev_rel` chain back-pointer within a rel record (used by the store's
/// no-op-undo relink, `rmp` #220).
pub(crate) const REL_OFF_START_PREV: usize = 61; // u64
const REL_OFF_START_NEXT: usize = 69; // u64
/// Byte offset of the `end_prev_rel` chain back-pointer within a rel record (used by the store's
/// no-op-undo relink, `rmp` #220).
pub(crate) const REL_OFF_END_PREV: usize = 77; // u64
const REL_OFF_END_NEXT: usize = 85; // u64
/// Byte offset of the `first_prop` chain-head pointer within a relationship record (used by the
/// store's compare-and-set chain-head logical undo).
pub(crate) const REL_OFF_FIRST_PROP: usize = 93; // u64
/// Byte offset of the 1-byte `chain_flags` within a rel record (used by the store's no-op-undo
/// relink, `rmp` #220).
pub(crate) const REL_OFF_CHAIN_FLAGS: usize = 101; // u8

/// `chain_flags` bit: this relationship is first in the **start node's** incidence chain
/// (`04 §2.3`, "first-in-chain markers ... to store degree on the first record").
pub const CHAIN_FLAG_START_FIRST: u8 = 0b0000_0001;
/// `chain_flags` bit: this relationship is first in the **end node's** incidence chain.
pub const CHAIN_FLAG_END_FIRST: u8 = 0b0000_0010;

/// A relationship record (`04 §2.3`) — the heart of index-free adjacency.
///
/// Each relationship is threaded into **two** doubly-linked incidence lists at once: one through
/// its `start_node` (`start_prev_rel`/`start_next_rel`) and one through its `end_node`
/// (`end_prev_rel`/`end_next_rel`). A self-loop (`start_node == end_node`) is threaded into the
/// node's single chain twice — once via each pointer pair (`04 §2.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelRecord {
    /// The frozen MVCC prefix.
    pub mvcc: MvccHeader,
    /// Stable, never-reused public identity (`D-element-id`).
    pub element_id: ElementId,
    /// Relationship-type token id (`tokens.store`, `04 §2.6`).
    pub type_id: u32,
    /// Physical id of the source node.
    pub start_node: u64,
    /// Physical id of the target node.
    pub end_node: u64,
    /// Previous relationship in the **start node's** incidence chain (`0` = head).
    pub start_prev_rel: u64,
    /// Next relationship in the **start node's** incidence chain (`0` = tail).
    pub start_next_rel: u64,
    /// Previous relationship in the **end node's** incidence chain (`0` = head).
    pub end_prev_rel: u64,
    /// Next relationship in the **end node's** incidence chain (`0` = tail).
    pub end_next_rel: u64,
    /// Physical id of the first property in this relationship's chain (`0` = none).
    pub first_prop: u64,
    /// First-in-chain markers ([`CHAIN_FLAG_START_FIRST`], [`CHAIN_FLAG_END_FIRST`]).
    pub chain_flags: u8,
}

impl RelRecord {
    /// A fresh, live relationship of `type_id` from `start_node` to `end_node`, not yet threaded
    /// into either incidence chain.
    #[must_use]
    pub fn new(
        element_id: ElementId,
        created_ts: u64,
        type_id: u32,
        start_node: u64,
        end_node: u64,
    ) -> Self {
        Self {
            mvcc: MvccHeader::live(created_ts),
            element_id,
            type_id,
            start_node,
            end_node,
            start_prev_rel: 0,
            start_next_rel: 0,
            end_prev_rel: 0,
            end_next_rel: 0,
            first_prop: 0,
            chain_flags: 0,
        }
    }

    /// Decodes a relationship record from a [`REL_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`REL_RECORD_SIZE`].
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        assert!(buf.len() >= REL_RECORD_SIZE, "rel record slice too short");
        Self {
            mvcc: MvccHeader::read(buf),
            element_id: ElementId(read_u128(buf, REL_OFF_ELEMENT_ID)),
            type_id: read_u32(buf, REL_OFF_TYPE),
            start_node: read_u64(buf, REL_OFF_START_NODE),
            end_node: read_u64(buf, REL_OFF_END_NODE),
            start_prev_rel: read_u64(buf, REL_OFF_START_PREV),
            start_next_rel: read_u64(buf, REL_OFF_START_NEXT),
            end_prev_rel: read_u64(buf, REL_OFF_END_PREV),
            end_next_rel: read_u64(buf, REL_OFF_END_NEXT),
            first_prop: read_u64(buf, REL_OFF_FIRST_PROP),
            chain_flags: buf[REL_OFF_CHAIN_FLAGS],
        }
    }

    /// Encodes this relationship record into a [`REL_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`REL_RECORD_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= REL_RECORD_SIZE, "rel record slice too short");
        self.mvcc.write(buf);
        write_u128(buf, REL_OFF_ELEMENT_ID, self.element_id.0);
        write_u32(buf, REL_OFF_TYPE, self.type_id);
        write_u64(buf, REL_OFF_START_NODE, self.start_node);
        write_u64(buf, REL_OFF_END_NODE, self.end_node);
        write_u64(buf, REL_OFF_START_PREV, self.start_prev_rel);
        write_u64(buf, REL_OFF_START_NEXT, self.start_next_rel);
        write_u64(buf, REL_OFF_END_PREV, self.end_prev_rel);
        write_u64(buf, REL_OFF_END_NEXT, self.end_next_rel);
        write_u64(buf, REL_OFF_FIRST_PROP, self.first_prop);
        buf[REL_OFF_CHAIN_FLAGS] = self.chain_flags;
    }

    /// The `(prev, next)` chain pointers for the endpoint that is `node`.
    ///
    /// For a self-loop, `which == ChainSide::Start` selects the `start_*` pair and
    /// `ChainSide::End` the `end_*` pair, so a self-loop's two chain memberships are
    /// distinguishable (`04 §2.4`).
    #[must_use]
    pub fn chain_pointers(&self, which: ChainSide) -> (u64, u64) {
        match which {
            ChainSide::Start => (self.start_prev_rel, self.start_next_rel),
            ChainSide::End => (self.end_prev_rel, self.end_next_rel),
        }
    }

    /// Sets the `(prev, next)` chain pointers for the given side.
    pub fn set_chain_pointers(&mut self, which: ChainSide, prev: u64, next: u64) {
        match which {
            ChainSide::Start => {
                self.start_prev_rel = prev;
                self.start_next_rel = next;
            }
            ChainSide::End => {
                self.end_prev_rel = prev;
                self.end_next_rel = next;
            }
        }
    }
}

/// Which of a relationship's two incidence-chain memberships is meant — the one threaded through
/// its `start_node` or the one threaded through its `end_node`.
///
/// For a self-loop both sides belong to the same node; this enum keeps them distinct so the
/// chain stays a well-formed doubly-linked list (`04 §2.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSide {
    /// The membership threaded through the relationship's `start_node`.
    Start,
    /// The membership threaded through the relationship's `end_node`.
    End,
}

// ============================= Property record =============================

/// Size of a property record in bytes (`04 §2.3`): MVCC header + `key` + `type_tag` +
/// `value_inline` + `next_prop`.
pub const PROP_RECORD_SIZE: usize = 46;

const PROP_OFF_KEY: usize = 25; // u32
const PROP_OFF_TYPE_TAG: usize = 29; // u8
const PROP_OFF_VALUE_INLINE: usize = 30; // u64
const PROP_OFF_NEXT_PROP: usize = 38; // u64

/// A property record (`04 §2.3`): one entry of an entity's singly-linked property chain.
///
/// `type_tag` discriminates the value class and the inline-vs-overflow bit (`04 §2.3`);
/// `value_inline` holds the value if it fits (e.g. an `i64`/`f64`/`bool`/short string) or else a
/// `strings.store` block id. The string/overflow heap is a follow-up task; this codec stores and
/// round-trips both fields opaquely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropRecord {
    /// The frozen MVCC prefix.
    pub mvcc: MvccHeader,
    /// Property-key token id (`tokens.store`, `04 §2.6`).
    pub key: u32,
    /// Value-class + inline/overflow discriminant (`04 §2.3`).
    pub type_tag: u8,
    /// The inline value, or a `strings.store` block id for overflowed values.
    pub value_inline: u64,
    /// Physical id of the next property in this entity's chain (`0` = end).
    pub next_prop: u64,
}

impl PropRecord {
    /// A fresh, live property with the given key, type tag and inline value, at the end of a
    /// chain (`next_prop == 0`).
    #[must_use]
    pub fn new(created_ts: u64, key: u32, type_tag: u8, value_inline: u64) -> Self {
        Self {
            mvcc: MvccHeader::live(created_ts),
            key,
            type_tag,
            value_inline,
            next_prop: 0,
        }
    }

    /// Decodes a property record from a [`PROP_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`PROP_RECORD_SIZE`].
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        assert!(buf.len() >= PROP_RECORD_SIZE, "prop record slice too short");
        Self {
            mvcc: MvccHeader::read(buf),
            key: read_u32(buf, PROP_OFF_KEY),
            type_tag: buf[PROP_OFF_TYPE_TAG],
            value_inline: read_u64(buf, PROP_OFF_VALUE_INLINE),
            next_prop: read_u64(buf, PROP_OFF_NEXT_PROP),
        }
    }

    /// Encodes this property record into a [`PROP_RECORD_SIZE`]-byte slice.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`PROP_RECORD_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= PROP_RECORD_SIZE, "prop record slice too short");
        self.mvcc.write(buf);
        write_u32(buf, PROP_OFF_KEY, self.key);
        buf[PROP_OFF_TYPE_TAG] = self.type_tag;
        write_u64(buf, PROP_OFF_VALUE_INLINE, self.value_inline);
        write_u64(buf, PROP_OFF_NEXT_PROP, self.next_prop);
    }
}

// ----------------------- little-endian scalar helpers -----------------------

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4-byte slice"))
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8-byte slice"))
}

fn read_u128(b: &[u8], off: usize) -> u128 {
    u128::from_le_bytes(b[off..off + 16].try_into().expect("16-byte slice"))
}

fn write_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn write_u128(b: &mut [u8], off: usize, v: u128) {
    b[off..off + 16].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_sizes_match_the_spec() {
        // 05 §7 froze the 25-byte MVCC prefix; 04 §2.3 froze the type-specific tails.
        assert_eq!(MVCC_HEADER_SIZE, 25);
        assert_eq!(NODE_RECORD_SIZE, 65);
        assert_eq!(REL_RECORD_SIZE, 102);
        assert_eq!(PROP_RECORD_SIZE, 46);
    }

    #[test]
    fn mvcc_header_round_trips_every_field() {
        let h = MvccHeader {
            flags: FLAG_IN_USE | FLAG_DENSE,
            created_ts: 0x0102_0304_0506_0708,
            expired_ts: 0x1111_2222_3333_4444,
            undo_ptr: 0xDEAD_BEEF_CAFE_F00D,
        };
        let mut buf = [0u8; MVCC_HEADER_SIZE];
        h.write(&mut buf);
        assert_eq!(MvccHeader::read(&buf), h);
        assert!(h.in_use());
        assert!(h.dense());
    }

    #[test]
    fn live_header_is_in_use_not_dense_not_expired() {
        let h = MvccHeader::live(42);
        assert!(h.in_use());
        assert!(!h.dense());
        assert_eq!(h.expired_ts, 0);
        assert_eq!(h.undo_ptr, 0);
    }

    #[test]
    fn node_record_round_trips() {
        let mut n = NodeRecord::new(ElementId(0xABCD_1234_5678_9012_3456_7890_ABCD_EF01), 7);
        n.first_rel = 11;
        n.first_prop = 22;
        n.labels = 0x00FF_00FF;
        let mut buf = [0u8; NODE_RECORD_SIZE];
        n.encode(&mut buf);
        assert_eq!(NodeRecord::decode(&buf), n);
    }

    #[test]
    fn rel_record_round_trips_with_both_chain_pairs() {
        let mut r = RelRecord::new(ElementId(99), 3, 5, 100, 200);
        r.set_chain_pointers(ChainSide::Start, 1, 2);
        r.set_chain_pointers(ChainSide::End, 3, 4);
        r.first_prop = 77;
        r.chain_flags = CHAIN_FLAG_START_FIRST | CHAIN_FLAG_END_FIRST;
        let mut buf = [0u8; REL_RECORD_SIZE];
        r.encode(&mut buf);
        let got = RelRecord::decode(&buf);
        assert_eq!(got, r);
        assert_eq!(got.chain_pointers(ChainSide::Start), (1, 2));
        assert_eq!(got.chain_pointers(ChainSide::End), (3, 4));
    }

    #[test]
    fn prop_record_round_trips() {
        let mut p = PropRecord::new(8, 3, 0x10, 0x4000_0000_0000_0001);
        p.next_prop = 5;
        let mut buf = [0u8; PROP_RECORD_SIZE];
        p.encode(&mut buf);
        assert_eq!(PropRecord::decode(&buf), p);
    }

    #[test]
    fn fields_are_little_endian_at_the_frozen_offsets() {
        // Guard the exact frozen byte layout (05 §7 + 04 §2.3), not just self-consistency.
        let mut r = RelRecord::new(ElementId(0), 0, 0xAABB_CCDD, 0, 0);
        let mut buf = [0u8; REL_RECORD_SIZE];
        r.encode(&mut buf);
        assert_eq!(
            &buf[REL_OFF_TYPE..REL_OFF_TYPE + 4],
            &[0xDD, 0xCC, 0xBB, 0xAA]
        );
        r.start_node = 0x0102_0304_0506_0708;
        r.encode(&mut buf);
        assert_eq!(
            &buf[REL_OFF_START_NODE..REL_OFF_START_NODE + 8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }
}
