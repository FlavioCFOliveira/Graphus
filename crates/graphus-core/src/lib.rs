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

pub use error::{CONSTRAINT_VIOLATION_PREFIX, GraphusError, Result};
pub use ids::{ElementId, Lsn, PageId, Timestamp, TxnId};
pub use temporal_calc::{TemporalError, TemporalResult};
pub use value::Value;
pub use value::spatial::{Crs, Point, total_f64};
pub use value::temporal::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};
pub use version::{MAX_TIMESTAMP, VersionStamp};

/// Calendar conversions, validated construction, openCypher component
/// accessors, ISO-8601 parsing/formatting, and arithmetic for the temporal
/// value types in [`value::temporal`].
pub mod temporal_calc;

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
            /// Sub-second nanoseconds (may be negative to share the seconds' sign in
            /// some constructions; consumers normalise as needed).
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
    /// On-disk format version, bumped on any incompatible layout change.
    pub const FORMAT_VERSION: u32 = 1;

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
