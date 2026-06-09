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

pub use error::{GraphusError, Result};
pub use ids::{ElementId, Lsn, PageId, Timestamp, TxnId};
pub use value::Value;
pub use value::temporal::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};

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

/// The Cypher value model (`01-needs-survey.md` FR-DM-6, FR-QL-5).
///
/// Covers the scalar, list, map and **temporal** value classes here. The spatial
/// (`Point`) and structural (node / relationship / path) variants are introduced
/// together with their owning subsystems. Cypher equality and ordering are
/// three-valued and are implemented in `graphus-cypher` (FR-QL-8); the derived
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
    pub use temporal::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};

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
        /// `i32` days spans roughly ±5.8 million years, far beyond any practical
        /// range, while keeping a compact fixed-width key component.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct Date {
            /// Days since 1970-01-01 (negative for earlier dates).
            pub days_since_epoch: i32,
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
        ZonedDateTime(ZonedDateTime),
        /// A Cypher duration (months / days / seconds / nanoseconds).
        Duration(Duration),
        // Point, Node, Relationship, and Path variants are added with their owning
        // subsystems (see specification/04-technical-design.md §7.2).
    }

    impl Value {
        /// Returns `true` if this value is [`Value::Null`].
        #[must_use]
        pub fn is_null(&self) -> bool {
            matches!(self, Value::Null)
        }
    }

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
            let _ = Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 0,
                    nanos: 0,
                },
                offset_seconds: 0,
                zone_id: "Europe/Lisbon".to_owned(),
            });
            assert!(!Value::Duration(Duration::default()).is_null());
        }
    }
}

/// The Graphus error taxonomy. Concrete variants grow per subsystem.
pub mod error {
    use std::fmt;

    /// The crate-wide result alias.
    pub type Result<T> = std::result::Result<T, GraphusError>;

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
    }

    impl fmt::Display for GraphusError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Storage(m) => write!(f, "storage error: {m}"),
                Self::Transaction(m) => write!(f, "transaction error: {m}"),
                Self::Compile(m) => write!(f, "compile error: {m}"),
                Self::Runtime(m) => write!(f, "runtime error: {m}"),
                Self::Protocol(m) => write!(f, "protocol error: {m}"),
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
    /// A monotonic clock source.
    pub trait Clock {
        /// Nanoseconds since an arbitrary fixed epoch (monotonic, non-decreasing).
        fn now_nanos(&self) -> u64;
    }

    /// A deterministic, seedable pseudo-random source.
    pub trait Rng {
        /// Returns the next pseudo-random `u64`.
        fn next_u64(&mut self) -> u64;
    }
}
