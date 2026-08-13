//! `graphus-core` — shared vocabulary for the Graphus LPG database server.
//!
//! This crate defines the foundational identifier newtypes, the Cypher [`Value`]
//! model, the error taxonomy, the capability traits the rest of the system is
//! parameterized over (for deterministic simulation testing), and global on-disk
//! format constants. See `specification/04-technical-design.md` §1.2.
//!
//! This is the skeleton established by the Phase 1 scaffolding task; subsystem
//! detail is filled in just-in-time by the owning Phase 1 tasks.
#![forbid(unsafe_code)]

pub use error::{
    CONSTRAINT_VIOLATION_PREFIX, GraphusError, Result, SCHEMA_RULE_ERROR_PREFIX,
    SCHEMA_RULE_ERROR_SEP, WIRE_STATUS_CODE_PREFIX, WIRE_STATUS_CODE_SEP, wire_status_code_message,
};
pub use ids::{CommandId, ElementId, Lsn, PageId, Timestamp, TxnId};
pub use temporal_calc::{TemporalError, TemporalResult};
pub use value::Value;
pub use value::numeric::cmp_int_float;
pub use value::spatial::{Crs, Point, total_f64};
pub use value::temporal::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};
pub use version::{HeaderStamp, MAX_TIMESTAMP, VersionStamp};

/// Calendar conversions, validated construction, openCypher component
/// accessors, ISO-8601 parsing/formatting, and arithmetic for the temporal
/// value types in [`value::temporal`].
pub mod temporal_calc;

/// IANA time-zone rules: resolving a named zone to a UTC offset, in both directions
/// (instant → offset, and local wall clock → offset with the DST gap/overlap rules).
pub mod timezone;

/// Verbatim Neo4j status codes for the driver-observable transaction failures, and the constructors
/// that pair each code with a carrier [`GraphusError`] variant of the same classification
/// (`rmp` task #988). This is where "may the client retry this?" is decided — see the module docs.
pub mod status;

/// The frame-latch tripwire (`rmp` #974): a debug-build guard proving that no durability barrier is
/// ever issued while a buffer-pool frame latch is held. Compiled out of release builds.
pub mod latch;

/// The deterministic writer-scheduling seam (`rmp` #973): the yield points through which a DST run
/// takes control of real-thread interleaving, so a concurrency defect reproduces from a seed. Gated
/// on the `det-sched` cargo feature; zero cost — and, for the installation API, non-existent — off.
pub mod sched;

/// Identifier newtypes used across the storage, transaction, and query layers.
pub mod ids {
    /// Physical page identifier within a store file.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct PageId(pub u64);

    /// Log sequence number, monotonic per the write-ahead log.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct Lsn(pub u64);

    /// Transaction identifier.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct TxnId(pub u64);

    /// Logical timestamp issued by the transaction timestamp oracle.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct Timestamp(pub u64);

    /// The statement counter within one transaction (`04 §5.1.4`).
    ///
    /// A transaction's first statement runs at [`CommandId::FIRST`] and each subsequent statement
    /// advances it by one. Every undo delta records the command that produced it, which is what lets
    /// a statement be shown the state that preceded it even for changes its **own** transaction made
    /// (the `OLD` view of `graphus_txn::View`).
    ///
    /// It is a `u32` because that is the width `05 §12.2` froze for the delta's `command_id` field.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct CommandId(pub u32);

    impl CommandId {
        /// The command a transaction's **first** statement runs at.
        ///
        /// It is `1`, not `0`, so that the `OLD` view of the first statement (`command_id <
        /// FIRST`) excludes every delta the transaction could possibly have written — `0` is
        /// reserved as "no statement has run yet" and is what a delta written outside any statement
        /// carries.
        pub const FIRST: Self = Self(1);

        /// The value a delta carries when no statement was in progress: maintenance and recovery
        /// writes, which no `OLD` view is ever resolved against.
        pub const NONE: Self = Self(0);

        /// The next command in the same transaction.
        ///
        /// Saturating rather than wrapping: a transaction that somehow issued `u32::MAX` statements
        /// keeps a monotonic counter — the alternative wraps to `0` and would make a later
        /// statement's own writes look older than its first, which is a visibility error rather
        /// than an overflow.
        #[must_use]
        pub const fn next(self) -> Self {
            Self(self.0.saturating_add(1))
        }
    }

    /// Stable, never-reused public element identifier (decision `D-element-id`).
    ///
    /// 128-bit and time-sortable (ULID / UUIDv7 class). The exact textual encoding
    /// is an open spike (`04-technical-design.md` §12 item 1); the raw 128-bit value
    /// is stored here and rendered as zero-padded lowercase hex.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct ElementId(pub u128);

    impl std::fmt::Display for ElementId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:032x}", self.0)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn element_id_renders_as_32_hex_digits() {
            assert_eq!(ElementId(1).to_string(), "00000000000000000000000000000001");
            assert_eq!(ElementId(0).to_string().len(), 32);
        }

        #[test]
        fn ids_are_ordered_by_value() {
            assert!(Lsn(1) < Lsn(2));
            assert!(PageId(10) > PageId(9));
        }
    }
}

/// The MVCC version-stamp convention shared by the frozen record header and the transaction
/// manager (`04-technical-design.md` §5.2, `05-storage-format.md` §7).
///
/// The frozen MVCC record header (`graphus_storage::record::MvccHeader`) stores `created_ts`
/// (a.k.a. `xmin`) and `expired_ts` (a.k.a. `xmax`) as raw `u64`s. A single field must encode
/// **either** a committed [`Timestamp`] **or** the [`TxnId`] of a still-in-flight writer, so both
/// the storage codec (which stamps the words) and the transaction visibility logic (which reads
/// them) must agree on one convention. It lives here, in the dependency-free core, so it is the
/// single source of truth for both crates rather than duplicated bit-twiddling.
pub mod version {
    use crate::ids::{Timestamp, TxnId};

    /// The high bit that marks a [`VersionStamp`] word as an in-flight [`TxnId`] rather than a
    /// committed commit-[`Timestamp`] (`04 §5.2`).
    const INFLIGHT_BIT: u64 = 1 << 63;

    /// Mask selecting the payload (low 63 bits) of a [`VersionStamp`] word.
    const PAYLOAD_MASK: u64 = INFLIGHT_BIT - 1;

    /// The largest timestamp the oracle may ever issue, so a committed stamp never collides with
    /// the `INFLIGHT_BIT`. In practice unreachable, but enforced so the convention can never
    /// silently alias.
    pub const MAX_TIMESTAMP: u64 = PAYLOAD_MASK;

    /// A typed view over the single `u64` stored in an MVCC header's `created_ts`/`expired_ts`
    /// field.
    ///
    /// It is **either** a committed commit-[`Timestamp`] **or** an in-flight [`TxnId`],
    /// discriminated by `INFLIGHT_BIT` (`04 §5.2`). The `0` word is the frozen *none/live*
    /// sentinel and decodes to [`VersionStamp::None`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VersionStamp {
        /// The sentinel `0`: no creator recorded, or (for `expired_ts`) the version is live.
        None,
        /// A committed transaction's commit timestamp.
        Committed(Timestamp),
        /// A still-in-flight writer, identified by its [`TxnId`].
        InFlight(TxnId),
    }

    impl VersionStamp {
        /// Decodes the raw header word into a typed stamp.
        #[must_use]
        pub fn from_raw(word: u64) -> Self {
            if word == 0 {
                Self::None
            } else if word & INFLIGHT_BIT != 0 {
                Self::InFlight(TxnId(word & PAYLOAD_MASK))
            } else {
                Self::Committed(Timestamp(word))
            }
        }

        /// Encodes this stamp back into the raw header word.
        #[must_use]
        pub fn to_raw(self) -> u64 {
            match self {
                Self::None => 0,
                Self::Committed(ts) => ts.0,
                Self::InFlight(txn) => INFLIGHT_BIT | (txn.0 & PAYLOAD_MASK),
            }
        }

        /// The header word for an in-flight writer `txn` (its `created_ts` until commit).
        ///
        /// # Panics
        /// Panics if `txn` is `TxnId(0)` (reserved) or its id does not fit in 63 bits, because
        /// either would corrupt the discriminant. These are manager invariants, not user input.
        #[must_use]
        pub fn in_flight(txn: TxnId) -> u64 {
            assert!(txn.0 != 0, "TxnId(0) is reserved and is never a writer");
            assert!(
                txn.0 & INFLIGHT_BIT == 0,
                "TxnId must fit in 63 bits for the version-stamp discriminant"
            );
            Self::InFlight(txn).to_raw()
        }

        /// The header word for a committed version created/expired at `ts`.
        #[must_use]
        pub fn committed(ts: Timestamp) -> u64 {
            Self::Committed(ts).to_raw()
        }
    }

    /// A typed view over the single `u64` stored in an MVCC **record header**'s
    /// `created_ts`/`expired_ts` field, from `rmp` #1069 phase 3 on.
    ///
    /// # Why this is a different type from [`VersionStamp`]
    ///
    /// The two share the **bit layout** exactly — `0` is the sentinel, the high bit discriminates,
    /// the low 63 bits are the payload — and differ in what the payload *means*:
    ///
    /// | Type | High bit set means | Resolved by |
    /// | --- | --- | --- |
    /// | [`VersionStamp`] | the payload is a [`TxnId`] | the in-memory Active/Recent Transaction Table |
    /// | [`HeaderStamp`] | the payload is a **`commit.store` slot id** | a durable read of that slot |
    ///
    /// Before `rmp` #1069 phase 3 a record header carried the first form, which is why resolving it
    /// needed an in-memory table (and therefore an `O(N)` freeze sweep, a freeze frontier and a WAL
    /// retention floor). It now carries the second, so the durable commit slot is the **single**
    /// commit oracle. [`VersionStamp`] is untouched and keeps serving
    /// `graphus_storage::undo::CommitSlot::commit_ts`, whose payload is and stays a [`TxnId`].
    ///
    /// Both populations are `u64` and both decode through either type without complaint, so the
    /// compiler cannot catch a mix-up — **two populations, two types** is the only guard, and it is
    /// the reason this type exists rather than a second set of helpers on [`VersionStamp`].
    /// Resolving a slot id as though it were a transaction id (or the reverse) is a type-correct
    /// call that produces silently wrong visibility.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HeaderStamp {
        /// The sentinel `0`: no creator recorded, or (for `expired_ts`) the version is live.
        None,
        /// A settled (frozen) stamp: the creating/expiring transaction's commit timestamp, readable
        /// with no indirection at all.
        Committed(Timestamp),
        /// An unsettled stamp: the physical id of the writer's slot in `commit.store`, whose
        /// `commit_ts` says what became of it.
        Slot(u64),
    }

    impl HeaderStamp {
        /// Decodes the raw header word into a typed stamp.
        #[must_use]
        pub fn from_raw(word: u64) -> Self {
            if word == 0 {
                Self::None
            } else if word & INFLIGHT_BIT != 0 {
                Self::Slot(word & PAYLOAD_MASK)
            } else {
                Self::Committed(Timestamp(word))
            }
        }

        /// Encodes this stamp back into the raw header word.
        #[must_use]
        pub fn to_raw(self) -> u64 {
            match self {
                Self::None => 0,
                Self::Committed(ts) => ts.0,
                Self::Slot(id) => INFLIGHT_BIT | (id & PAYLOAD_MASK),
            }
        }

        /// The commit slot this word names, if it names one — `None` for the sentinel and for an
        /// already-settled `Committed` word, neither of which resolves through `commit.store`.
        ///
        /// This is the reachability question the undo area's reference census asks of every in-use
        /// record header (`rmp` #1069 phase 1): a slot that a header still names must never be
        /// returned to circulation.
        #[must_use]
        pub fn slot_id(self) -> Option<u64> {
            match self {
                Self::Slot(id) => Some(id),
                Self::None | Self::Committed(_) => None,
            }
        }

        /// The header word naming commit slot `id`.
        ///
        /// # Panics
        /// Panics if `id` is `0` (the `NULL_ID` no store ever allocates) or does not fit in 63 bits,
        /// because either would corrupt the discriminant — `0` would make the word indistinguishable
        /// from a real slot reference that resolves nowhere. These are store invariants, not user
        /// input.
        #[must_use]
        pub fn slot(id: u64) -> u64 {
            assert!(id != 0, "slot id 0 is NULL_ID and is never allocated");
            assert!(
                id & INFLIGHT_BIT == 0,
                "commit slot id must fit in 63 bits for the header-stamp discriminant"
            );
            Self::Slot(id).to_raw()
        }

        /// The header word for a settled version created/expired at `ts`.
        ///
        /// Byte-identical to [`VersionStamp::committed`] — a settled word carries no indirection, so
        /// the two populations agree on it exactly, and a store frozen before `rmp` #1069 phase 3
        /// reads correctly under either convention.
        #[must_use]
        pub fn committed(ts: Timestamp) -> u64 {
            Self::Committed(ts).to_raw()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn stamp_round_trips_each_class() {
            assert_eq!(VersionStamp::from_raw(0), VersionStamp::None);
            assert_eq!(
                VersionStamp::from_raw(VersionStamp::committed(Timestamp(7))),
                VersionStamp::Committed(Timestamp(7))
            );
            assert_eq!(
                VersionStamp::from_raw(VersionStamp::in_flight(TxnId(42))),
                VersionStamp::InFlight(TxnId(42))
            );
        }

        #[test]
        fn committed_and_inflight_never_alias() {
            let raw_commit = VersionStamp::committed(Timestamp(100));
            let raw_inflight = VersionStamp::in_flight(TxnId(100));
            assert_ne!(raw_commit, raw_inflight);
            assert!(matches!(
                VersionStamp::from_raw(raw_commit),
                VersionStamp::Committed(_)
            ));
            assert!(matches!(
                VersionStamp::from_raw(raw_inflight),
                VersionStamp::InFlight(_)
            ));
        }

        #[test]
        #[should_panic(expected = "reserved")]
        fn inflight_zero_txn_panics() {
            let _ = VersionStamp::in_flight(TxnId(0));
        }

        // ---- `HeaderStamp` (`rmp` #1069 phase 3) ----

        #[test]
        fn header_stamp_round_trips_each_class() {
            assert_eq!(HeaderStamp::from_raw(0), HeaderStamp::None);
            assert_eq!(
                HeaderStamp::from_raw(HeaderStamp::committed(Timestamp(7))),
                HeaderStamp::Committed(Timestamp(7))
            );
            assert_eq!(
                HeaderStamp::from_raw(HeaderStamp::slot(42)),
                HeaderStamp::Slot(42)
            );
        }

        #[test]
        fn header_stamp_slot_id_names_only_unsettled_words() {
            assert_eq!(HeaderStamp::from_raw(0).slot_id(), None);
            assert_eq!(
                HeaderStamp::from_raw(HeaderStamp::committed(Timestamp(7))).slot_id(),
                None
            );
            assert_eq!(
                HeaderStamp::from_raw(HeaderStamp::slot(42)).slot_id(),
                Some(42)
            );
        }

        /// The bit LAYOUT is unchanged by `rmp` #1069 phase 3 — only the payload's meaning is. This
        /// pins that: a slot-id word and a `TxnId` word with the same numeric payload are the SAME
        /// bytes, which is exactly why the format version had to be bumped (a pre-phase-3 image read
        /// under the new convention is silently misread, in both directions).
        #[test]
        fn header_and_version_stamps_share_the_bit_layout() {
            assert_eq!(HeaderStamp::slot(42), VersionStamp::in_flight(TxnId(42)));
            assert_eq!(
                HeaderStamp::committed(Timestamp(7)),
                VersionStamp::committed(Timestamp(7))
            );
        }

        #[test]
        #[should_panic(expected = "NULL_ID")]
        fn header_stamp_slot_zero_panics() {
            let _ = HeaderStamp::slot(0);
        }
    }
}

/// The Cypher value model (`01-needs-survey.md` FR-DM-6, FR-QL-5).
///
/// Covers the scalar, list, map, **temporal** and **spatial** (`Point`) value
/// classes here. The structural (node / relationship / path) variants are
/// introduced together with their owning subsystems. Cypher equality and ordering
/// are three-valued and are implemented in `graphus-cypher` (FR-QL-8); the derived
/// [`PartialEq`] here is structural and is **not** the Cypher equality operator.
///
/// The temporal variants ([`Date`](Value::Date), [`LocalTime`](Value::LocalTime),
/// [`ZonedTime`](Value::ZonedTime), [`LocalDateTime`](Value::LocalDateTime),
/// [`ZonedDateTime`](Value::ZonedDateTime), [`Duration`](Value::Duration)) were
/// added additively for the Cypher value-model semantics sub-task. They use small,
/// fixed-width component representations at **nanosecond resolution**, modelled
/// directly on the openCypher temporal types (CIP2016-06-14 §Orderability and the
/// temporal CIP). Their cross-class ordering rank is defined in `graphus-cypher`'s
/// `ordering` module and mirrored in `graphus-index`'s `keycodec`.
pub mod value {
    pub use spatial::{Crs, Point};
    pub use temporal::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};

    /// The spatial **point** value class (CRS + 2D/3D `f64` coordinates), its equality and its total
    /// ordering. Modelled on [`temporal`] (storage-shaped, fixed-width components); see
    /// `04-technical-design.md` §7.2 and `rmp` task #73.
    pub mod spatial;

    /// The exact comparison between the two Cypher numeric types (`INTEGER` / `FLOAT`), the single
    /// primitive all three of Cypher's value relations build on (`rmp` task #894).
    pub mod numeric;

    /// Fixed-width temporal component types used by the temporal [`Value`] variants.
    ///
    /// These deliberately store **decomposed integer components** (not a single
    /// instant) so that the order-preserving index key encoding can lay them out
    /// most-significant-component-first and so that Cypher's component-wise temporal
    /// semantics are representable. All resolutions are nanosecond. Modelled on the
    /// openCypher temporal CIP (see `specification/04-technical-design.md` §7.2).
    pub mod temporal {
        /// Nanoseconds in one standard (non-leap) day: `24 * 60 * 60 * 1_000_000_000`.
        pub const NANOS_PER_DAY: u64 = 86_400_000_000_000;

        /// A calendar date, as **days since the Unix epoch** (1970-01-01).
        ///
        /// `i64` days spans roughly ±25 billion years, which comfortably covers
        /// the full openCypher proleptic-Gregorian range of years
        /// `-999_999_999 ..= +999_999_999` (~±3.66e11 days) required by the TCK
        /// (`Temporal10.feature` "large durations"), while keeping a compact
        /// fixed-width key component.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct Date {
            /// Days since 1970-01-01 (negative for earlier dates).
            pub days_since_epoch: i64,
        }

        /// A wall-clock time of day with no date and no zone, as **nanoseconds since
        /// midnight** (`0 ..= NANOS_PER_DAY - 1`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct LocalTime {
            /// Nanoseconds since 00:00:00 (`< NANOS_PER_DAY`).
            pub nanos_of_day: u64,
        }

        /// A time of day with a fixed UTC offset but no date (openCypher `Time`).
        ///
        /// Two `ZonedTime`s are ordered by the **instant they denote** (local time
        /// minus offset), then by the offset to break ties between equal instants,
        /// so the ordering is total and matches the index key layout.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct ZonedTime {
            /// The wall-clock time of day.
            pub time: LocalTime,
            /// UTC offset in seconds (east of UTC positive), e.g. `+01:00` = `3600`.
            pub offset_seconds: i32,
        }

        /// A date-and-time with no zone, as **seconds since the Unix epoch** plus a
        /// sub-second nanosecond field (`0 ..= 999_999_999`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct LocalDateTime {
            /// Seconds since 1970-01-01T00:00:00 (negative for earlier instants).
            pub epoch_seconds: i64,
            /// Sub-second nanoseconds (`< 1_000_000_000`).
            pub nanos: u32,
        }

        /// A date-and-time with both a resolved UTC offset and an IANA zone id
        /// (openCypher `DateTime`).
        ///
        /// The IANA zone id (e.g. `"Europe/Lisbon"`) is retained for round-tripping
        /// and rendering, while the resolved `offset_seconds` is what fixes the
        /// **instant**. Ordering is by the underlying UTC instant (`local - offset`).
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
        pub struct ZonedDateTime {
            /// The local date-and-time as stored (interpreted in the zone/offset).
            pub local: LocalDateTime,
            /// Resolved UTC offset in seconds (east of UTC positive).
            pub offset_seconds: i32,
            /// IANA time-zone id (e.g. `"Europe/Lisbon"`), or empty if offset-only.
            pub zone_id: String,
        }

        /// A Cypher [`Duration`]: a quantity of months, days, seconds and nanoseconds.
        ///
        /// Cypher durations are **not** a single scalar of seconds — months and days
        /// are calendar-relative and are kept as independent components (a month is
        /// not a fixed number of days, a day is not always 86 400 s across DST). For
        /// ordering, Cypher compares durations by an approximate normalised length
        /// (see `graphus-cypher`'s `ordering` module); component-wise equality is the
        /// equality rule.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct Duration {
            /// Whole months.
            pub months: i64,
            /// Whole days (calendar days, not normalised into months).
            pub days: i64,
            /// Whole seconds.
            pub seconds: i64,
            /// Sub-second nanoseconds, **normalised** to `0 ..= 999_999_999`.
            ///
            /// Every producer normalises before constructing: `graphus-cypher`'s
            /// `temporal_fns` carries the overflow into `seconds` with
            /// `div_euclid`/`rem_euclid`, and the PackStream decoder does the same
            /// with the wider `i64` nanosecond field the wire allows (`rmp` #911,
            /// matching the reference `DurationValue` constructor). So a negative or
            /// ≥1e9 value is not a spelling this type carries — it is normalised
            /// away first. Equality is component-wise, so admitting alternative
            /// spellings would make one duration compare unequal to itself.
            pub nanos: i32,
        }
    }

    /// A Cypher value.
    #[derive(Debug, Clone, PartialEq, Default)]
    pub enum Value {
        /// The null value (participates in three-valued logic).
        #[default]
        Null,
        /// A boolean.
        Boolean(bool),
        /// A 64-bit signed integer (`i64`).
        Integer(i64),
        /// An IEEE-754 64-bit float (`f64`).
        Float(f64),
        /// A Unicode string.
        String(String),
        /// A byte string (REST/PackStream binary).
        Bytes(Vec<u8>),
        /// An ordered list of values.
        List(Vec<Value>),
        /// A map of string keys to values (insertion order preserved).
        Map(Vec<(String, Value)>),
        /// A calendar date (openCypher `Date`).
        Date(Date),
        /// A wall-clock time of day with no zone (openCypher `LocalTime`).
        LocalTime(LocalTime),
        /// A time of day with a fixed UTC offset (openCypher `Time`).
        ZonedTime(ZonedTime),
        /// A date-and-time with no zone (openCypher `LocalDateTime`).
        LocalDateTime(LocalDateTime),
        /// A date-and-time with a resolved offset and IANA zone (openCypher `DateTime`).
        ///
        /// Boxed: `ZonedDateTime` embeds an inline `String` zone id, making it the largest variant
        /// (48 B). Boxing this rare variant shrinks the whole `Value` enum (`rmp` finding B3). The
        /// box is transparent to `Clone`/`PartialEq`/ordering/serialization, which deref through it.
        ZonedDateTime(Box<ZonedDateTime>),
        /// A Cypher duration (months / days / seconds / nanoseconds).
        Duration(Duration),
        /// A spatial point (Cartesian / WGS-84, 2D or 3D; openCypher `Point`, `rmp` task #73). Its
        /// derived [`PartialEq`] is [`Point`]'s Cypher value equality (same CRS *and* equal
        /// coordinates); ordering lives in `graphus-cypher`'s `ordering` module and the index key
        /// codec, both consistent with [`Point::total_cmp`](spatial::Point::total_cmp).
        ///
        Point(Point),
        // Node, Relationship, and Path variants are added with their owning
        // subsystems (see specification/04-technical-design.md §7.2).
    }

    impl Value {
        /// Returns `true` if this value is [`Value::Null`].
        #[must_use]
        pub fn is_null(&self) -> bool {
            matches!(self, Value::Null)
        }

        /// Builds a [`Value::ZonedDateTime`] from an unboxed [`ZonedDateTime`].
        ///
        /// PERF/B3: the variant boxes its payload (the largest variant) to shrink `Value`. This
        /// constructor centralises the boxing so call sites stay readable and `.map(...)`-able.
        #[must_use]
        pub fn zoned_date_time(z: ZonedDateTime) -> Self {
            Value::ZonedDateTime(Box::new(z))
        }
    }

    // PERF (B3): `Value` is cloned/moved on every row and list element on the hot path, so its
    // stack footprint matters. Boxing the largest, rare variant (`ZonedDateTime`, 48 B — it embeds
    // an inline `String` zone id) shrank `Value` from 48 B to 40 B. The new floor is `Duration`
    // (32 B, a `Copy` POD of three `i64`s + an `i32`); boxing it was rejected because it is common
    // in temporal queries and boxing would cost an allocation per value and forfeit `Copy`. This
    // pins the win so a future fat variant that regresses it fails the build.
    const _: () = assert!(std::mem::size_of::<Value>() <= 40);

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn default_value_is_null() {
            assert!(Value::default().is_null());
        }

        #[test]
        fn non_null_values_are_not_null() {
            assert!(!Value::Integer(7).is_null());
            assert!(!Value::List(vec![Value::Null]).is_null());
        }

        #[test]
        fn temporal_variants_construct() {
            let _ = Value::Date(Date {
                days_since_epoch: 0,
            });
            let _ = Value::LocalTime(LocalTime { nanos_of_day: 1 });
            let _ = Value::ZonedTime(ZonedTime {
                time: LocalTime { nanos_of_day: 1 },
                offset_seconds: 3600,
            });
            let _ = Value::LocalDateTime(LocalDateTime {
                epoch_seconds: 0,
                nanos: 0,
            });
            let _ = Value::zoned_date_time(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 0,
                    nanos: 0,
                },
                offset_seconds: 0,
                zone_id: "Europe/Lisbon".to_owned(),
            });
            assert!(!Value::Duration(Duration::default()).is_null());
        }

        #[test]
        fn point_variants_construct() {
            use super::spatial::{Crs, Point};
            let p2 = Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0));
            let p3 = Value::Point(Point::new_3d(Crs::Wgs84_3D, 10.0, 20.0, 30.0));
            assert!(!p2.is_null());
            assert!(!p3.is_null());
            // Cypher value equality is the derived `PartialEq`: same CRS and coordinates.
            assert_eq!(
                Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0)),
                Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0))
            );
            // Same coordinates, different CRS ⇒ not equal.
            assert_ne!(
                Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0)),
                Value::Point(Point::new_2d(Crs::Wgs84, 1.0, 2.0))
            );
        }
    }
}

/// The Graphus error taxonomy. Concrete variants grow per subsystem.
pub mod error {
    use std::fmt;

    /// The crate-wide result alias.
    pub type Result<T> = std::result::Result<T, GraphusError>;

    /// The stable internal sentinel that prefixes a **constraint-violation** runtime-error message
    /// (`rmp` task #99; `04-technical-design.md` §6.5, §7.3).
    ///
    /// A unique/existence-constraint breach is a [`GraphusError::Runtime`] (its docs already name
    /// "constraint" as a runtime cause). To let the Bolt error renderer emit the precise schema class
    /// `Neo.ClientError.Schema.ConstraintValidationFailed` **without** widening this
    /// `#[non_exhaustive]` enum, the query layer prefixes the violation message with this sentinel and
    /// the Bolt layer detects + strips it. It lives in `graphus-core` so the producer (`graphus-cypher`)
    /// and the consumer (`graphus-bolt`) share one definition with **no** crate dependency between them
    /// (both depend on `graphus-core`). Chosen so a genuine user message can never start with it.
    pub const CONSTRAINT_VIOLATION_PREFIX: &str = "\u{1}constraint-violation\u{1} ";

    /// The stable internal sentinel that prefixes a **schema-rule** error message — an index/constraint
    /// name collision, an equivalent schema rule already existing, or a drop of a missing rule
    /// (`rmp` task #624). Carried on a [`GraphusError::Runtime`] whose message, after this prefix, is
    /// `<Neo4j leaf code>\u{1f}<human message>` (the [`SCHEMA_RULE_ERROR_SEP`] separates the two).
    ///
    /// The Bolt / REST error renderers detect the prefix, split off the precise `Neo.ClientError.Schema.*`
    /// leaf code and emit it (stripping the sentinel + code from the message the wire carries), exactly
    /// as they already do for [`CONSTRAINT_VIOLATION_PREFIX`]. It lives here in `graphus-core` so the
    /// producer (`graphus-cypher`) and the consumers (`graphus-bolt`, `graphus-rest`) share one
    /// definition with **no** crate dependency between them. Chosen so a genuine user message can never
    /// start with it, and — since the code segment is server-generated from a fixed set of leaf codes
    /// and any user-supplied name lands in the *human* segment after the first separator — a client can
    /// never inject an arbitrary status code.
    pub const SCHEMA_RULE_ERROR_PREFIX: &str = "\u{1}schema-rule-error\u{1} ";

    /// The separator between the Neo4j leaf code and the human message inside a message carrying
    /// [`SCHEMA_RULE_ERROR_PREFIX`] (`rmp` task #624). The ASCII unit separator (`0x1f`), which never
    /// appears in a leaf code or a human schema message.
    pub const SCHEMA_RULE_ERROR_SEP: char = '\u{1f}';

    /// The stable internal sentinel that prefixes an engine-error message carrying a **verbatim
    /// Neo4j leaf status code** to emit on the wire (`rmp` task #814). Its remainder is
    /// `<Neo4j leaf code>\u{1f}<human message>` (the [`WIRE_STATUS_CODE_SEP`] separates the two).
    ///
    /// This is the reusable, **variant-agnostic** generalization of [`SCHEMA_RULE_ERROR_PREFIX`]:
    /// where that one carries schema-rule leaf codes on a [`GraphusError::Runtime`] only, this one
    /// may ride ANY [`GraphusError`] variant, so it is the single primitive for "carry a
    /// driver-observable Neo4j leaf code from the engine to the wire" for the common codes an
    /// application switches on. The headline member is
    /// `Neo.ClientError.Database.DatabaseNotFound` for a request that names a database which does
    /// not exist (whose exact title a client may switch on — e.g. auto-create-on-not-found).
    ///
    /// The Bolt / REST error renderers detect the prefix, split off the precise `Neo.*` leaf code
    /// and emit it **verbatim** (stripping the sentinel + code from the human message the wire
    /// carries), exactly as they already do for [`SCHEMA_RULE_ERROR_PREFIX`]. It lives here in
    /// `graphus-core` so the producer (`graphus-server`) and the consumers (`graphus-bolt`,
    /// `graphus-rest`) share one definition with **no** crate dependency between them. Chosen so a
    /// genuine user message can never start with it; the code segment is server-generated from a
    /// fixed set of leaf codes and any client-supplied value lands in the *human* segment after the
    /// first separator, so a client can never inject an arbitrary status code.
    ///
    /// The carrier variant still matters as a **fallback classification**: a producer wraps the
    /// framed message in whichever [`GraphusError`] variant conveys the correct coarse class
    /// (client-fault vs. server-fault), so that even if a renderer did not strip the sentinel the
    /// classification the driver acts on (retry vs. fail) would still be right. The leaf code and
    /// its carrier variant MUST agree on classification (e.g. a `Neo.ClientError.*` leaf on a
    /// client-fault variant): the leaf code the wire carries changes only the fine-grained title,
    /// never the classification.
    pub const WIRE_STATUS_CODE_PREFIX: &str = "\u{1}wire-status-code\u{1} ";

    /// The separator between the Neo4j leaf code and the human message inside a message carrying
    /// [`WIRE_STATUS_CODE_PREFIX`] (`rmp` task #814). The ASCII unit separator (`0x1f`), which never
    /// appears in a leaf code or a human message.
    pub const WIRE_STATUS_CODE_SEP: char = '\u{1f}';

    /// Frames a **verbatim Neo4j leaf status code** together with its human message into the wire
    /// form the Bolt / REST error renderers decode (`rmp` task #814):
    /// `<WIRE_STATUS_CODE_PREFIX><leaf code>\u{1f}<message>`.
    ///
    /// Producers wrap the returned string in whichever [`GraphusError`] variant carries the right
    /// *fallback* classification (see [`WIRE_STATUS_CODE_PREFIX`]). `leaf_code` MUST be a
    /// server-controlled constant; `message` may contain user data — it lands after the separator
    /// and can never be read back as a status code.
    #[must_use]
    pub fn wire_status_code_message(leaf_code: &str, message: &str) -> String {
        format!("{WIRE_STATUS_CODE_PREFIX}{leaf_code}{WIRE_STATUS_CODE_SEP}{message}")
    }

    /// Top-level error type for Graphus.
    ///
    /// The compile/runtime split mirrors the openCypher TCK error-phase distinction
    /// (`01-needs-survey.md` FR-QL-9): compile-time errors are raised before any
    /// execution begins.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum GraphusError {
        /// A storage- or durability-layer failure.
        Storage(String),
        /// A transaction-layer failure (conflict, abort, deadlock).
        Transaction(String),
        /// A Cypher compile-time error (syntax / semantic), raised before execution.
        Compile(String),
        /// A Cypher runtime error (type / arithmetic / entity / constraint).
        Runtime(String),
        /// A protocol or connectivity error.
        Protocol(String),
        /// An authorization failure: the authenticated principal lacks the privilege the
        /// operation requires (`04 §8.4` deny-by-default RBAC). Distinct from
        /// [`GraphusError::Protocol`] so the connectivity layers can classify it as a
        /// permission-denied condition (Bolt `Neo.ClientError.Security.Forbidden`, HTTP `403`)
        /// rather than a malformed request.
        Security(String),
    }

    impl fmt::Display for GraphusError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Storage(m) => write!(f, "storage error: {m}"),
                Self::Transaction(m) => write!(f, "transaction error: {m}"),
                Self::Compile(m) => write!(f, "compile error: {m}"),
                Self::Runtime(m) => write!(f, "runtime error: {m}"),
                Self::Protocol(m) => write!(f, "protocol error: {m}"),
                Self::Security(m) => write!(f, "security error: {m}"),
            }
        }
    }

    impl std::error::Error for GraphusError {}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn display_is_prefixed_by_layer() {
            let e = GraphusError::Compile("unexpected token".to_owned());
            assert_eq!(e.to_string(), "compile error: unexpected token");
        }
    }
}

/// Global on-disk format and engine constants.
pub mod constants {
    /// On-disk format version, bumped on any **incompatible** change to the durable image —
    /// incompatible in **layout** or in **meaning**.
    ///
    /// | Version | Introduced by | Change |
    /// | --- | --- | --- |
    /// | 1 | — | Three record stores plus the `strings.store` overflow heap; `undo_ptr` reserved in every record header and permanently `0`. |
    /// | 2 | `rmp` #966 | The **undo area** (`05-storage-format.md` §12): the `undo.store` delta store and the `commit.store` commit-info store, and `undo_ptr` as the live head of an entity's version chain. A **layout** change. |
    /// | 3 | `rmp` #967 | A property cell's MVCC header no longer carries its visibility (`D-property-visibility`): the newest value lives in the cell and every older one on the owning entity's undo chain, so `expired_ts` is never stamped on a property cell again. A **meaning** change at identical layout — see below. |
    /// | 4 | `rmp` #1066 | The trailing **applied-transaction-set** catalog block — see below. |
    /// | 5 | `rmp` #1083 | The trailing **pending-DDL** catalog block — see below. |
    /// | 6 | `rmp` #1069 | A record header's unsettled stamp names a **`commit.store` slot** instead of a `TxnId`. A **meaning** change at identical layout — see below. |
    ///
    /// # Why a meaning change bumps the version too
    ///
    /// Version 3 adds no field and moves no byte: a version-2 and a version-3 catalog differ only in
    /// this number. What changed is how a `props.store` cell is *read*. Before #967 a committed
    /// `REMOVE n.p` was one cell left in use with `expired_ts` stamped and its value intact, and
    /// visibility came from that header; from #967 the undo chain is the sole oracle and the header is
    /// not consulted. A version-2 image read by a version-3 build therefore reports every committed
    /// property removal as a live property — a wrong answer that looks like data, which is worse than
    /// a failed startup. That is exactly the class of incompatibility this constant exists to express,
    /// so it is expressed here rather than left to be discovered at query time. The machinery is
    /// #966's and is merely used: the append-only catalog block that carries the number, and the
    /// bit-31 tripwire on the head metadata page that makes a pre-#966 build refuse rather than
    /// misread.
    ///
    /// The version is persisted in the durable catalog (`graphus_storage::Meta`), which is where a
    /// store's version is read from and where the compatibility decision is taken: a store older
    /// than this constant is **upgraded** on open — unless the upgrade would change what its data
    /// means, in which case it is **refused** with a migration route
    /// (`RecordStore::refuse_legacy_property_tombstones`) — and one newer than it is always refused.
    ///
    /// # Version 4 (`rmp` #1066): the applied-transaction set
    ///
    /// Version 4 appends one trailing block to the catalog image: the set of transactions whose
    /// logged cardinality deltas are already folded into the `Statistics` persisted beside it
    /// (`graphus_storage::AppliedTxSet`). The bump is what stops an older build from reading a
    /// version-4 image, and it has to: such a build would replay every count-delta record in the log
    /// — it does not know the record type, so it skips them — and, worse, would rewrite the catalog
    /// **without** the block, discarding the record of what had already been applied. The next
    /// version-4 build to open that store would then fold every still-retained delta in a second
    /// time. A counter that `count()` is answered from would be permanently wrong, silently.
    ///
    /// A version-3 image opened by this build is an **upgrade**, not a conversion: the block is
    /// simply absent and the set decodes empty, which is the truth for it — no build below version 4
    /// ever wrote a count-delta record, so there is nothing an empty set could cause to be applied
    /// twice. The first checkpoint rewrites the catalog with the block present.
    ///
    /// # Version 5 (`rmp` #1083): the committing transaction's pending schema DDL, attributed
    ///
    /// Version 5 appends a second trailing block: the schema-catalog DDL of the transaction whose
    /// commit wrote the image, carried **beside** the committed catalogue instead of inside it, and
    /// named by its transaction id. Until version 5 that DDL was folded into the persisted
    /// `Statistics` itself — the only route a committing `CREATE INDEX` / `CREATE CONSTRAINT` had to
    /// disk — so an image written by a transaction that then never committed left its DDL durable. A
    /// phantom `UNIQUE` constraint rejects writes that must be admitted, which is a correctness
    /// violation and not a cosmetic one. From version 5 the image carries only COMMITTED schema and
    /// `open` applies the block only for a transaction whose `COMMIT` record recovery found.
    ///
    /// The bump stops an older build from reading a version-5 image, and it has to for the same
    /// reason version 4's did in the opposite direction: such a build would ignore the block, so a
    /// committed `CREATE CONSTRAINT` whose only durable record is that block would silently vanish.
    ///
    /// A version-4 image opened by this build is an **upgrade**: the block is simply absent and
    /// decodes to "no pending DDL", which is the truth for it — a version-4 image already folded its
    /// committing transaction's DDL into the counters' `Statistics`, so there is nothing left to
    /// attribute and nothing to lose.
    ///
    /// # Version 6 (`rmp` #1069): a record header's unsettled stamp names a commit slot
    ///
    /// Version 6 moves not one byte. It changes what two `u64`s **mean**, and it is therefore the
    /// same class of bump as version 3 — the class this constant exists to express.
    ///
    /// Until version 6, an unsettled `MvccHeader::created_ts` / `expired_ts` carried the writer's
    /// [`TxnId`](crate::TxnId) ([`VersionStamp`](crate::VersionStamp)), translatable only by an
    /// **in-memory** table. From version 6 it carries the physical id of that writer's slot in
    /// `commit.store` ([`HeaderStamp`](crate::HeaderStamp)) — the same durable oracle the undo deltas
    /// already resolved through — so the engine has one commit oracle instead of two.
    ///
    /// The two encodings are **bit-identical**: same sentinel, same high-bit discriminant, same
    /// 63-bit payload. That is precisely why the bump is mandatory rather than optional. A small
    /// `TxnId` is a perfectly plausible slot id and a small slot id is a perfectly plausible `TxnId`,
    /// so a mis-versioned image is misread **silently, in both directions**, and the misreading
    /// attributes a committed version to an unrelated transaction — a wrong answer that looks like
    /// data.
    ///
    /// A pre-version-6 image is therefore not blindly refused but **examined**, exactly as version 3
    /// examines property tombstones: an image in which no in-use record carries an unsettled stamp is
    /// completely settled, has nothing that can be misread, and opens. One that does carry an
    /// unsettled stamp is refused with the offending record named, and with a migration route that is
    /// better than version 3's export/import — opening it with the previous build and forcing a full
    /// freeze settles every stamp, after which it opens here (`RecordStore::refuse_legacy_txn_stamps`).
    pub const FORMAT_VERSION: u32 = 6;

    /// Logical database page size in bytes, decoupled from the OS page size
    /// (`04-technical-design.md` §3.1; the default is subject to spike §12 item 4).
    pub const LOGICAL_PAGE_SIZE: usize = 8192;

    /// Magic number identifying a Graphus store file (ASCII "GRPH").
    pub const STORE_MAGIC: u32 = 0x4752_5048;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn logical_page_size_is_a_power_of_two() {
            assert!(LOGICAL_PAGE_SIZE.is_power_of_two());
        }
    }
}

/// Capability traits the engine is parameterized over, so the whole system can run
/// inside a deterministic simulator (`graphus-sim`) for DST (decision
/// `D-dst-investment`). Richer capabilities (file system, task spawning) arrive with
/// the I/O and runtime crates.
pub mod capability {
    /// A clock source.
    ///
    /// [`now_nanos`](Clock::now_nanos) is the **monotonic** timeline: it never goes backwards and is
    /// used for every *elapsed-time* and *idle/expiry* measurement (query latency, the REST
    /// transaction inactivity timeout). A production implementation MUST back it with a monotonic OS
    /// source (`CLOCK_MONOTONIC` / [`std::time::Instant`]) so a wall-clock adjustment (NTP step,
    /// operator change) can never make a duration wrap to zero or to a spurious multi-decade value.
    ///
    /// [`now_unix_nanos`](Clock::now_unix_nanos) is the **wall-clock** timeline: nanoseconds since the
    /// Unix epoch, used only where an *absolute* timestamp is required (e.g. JWT validity). It may
    /// jump forwards or backwards with the system clock — never use it to measure an interval.
    ///
    /// For a deterministic clock (the simulator / tests) the two timelines coincide, so
    /// `now_unix_nanos` defaults to `now_nanos`; only a clock whose monotonic and wall-clock sources
    /// genuinely diverge (the production [`SystemClock`](../../graphus_server/struct.SystemClock.html))
    /// overrides it.
    pub trait Clock {
        /// Monotonic nanoseconds since an arbitrary fixed epoch (non-decreasing). Use for **elapsed**
        /// and **idle/expiry** measurement only.
        fn now_nanos(&self) -> u64;

        /// Wall-clock nanoseconds since the Unix epoch, for **absolute** timestamps (e.g. JWT
        /// validity). Defaults to [`now_nanos`](Clock::now_nanos) for clocks whose monotonic and
        /// wall-clock timelines coincide (the deterministic simulator and tests). Never use this to
        /// measure an interval — it can step backwards with the system clock.
        fn now_unix_nanos(&self) -> u64 {
            self.now_nanos()
        }
    }

    /// A deterministic, seedable pseudo-random source.
    pub trait Rng {
        /// Returns the next pseudo-random `u64`.
        fn next_u64(&mut self) -> u64;
    }
}
