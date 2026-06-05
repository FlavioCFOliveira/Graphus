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
/// Covers the scalar/list core here; the temporal, spatial, and structural
/// (node / relationship / path) variants are introduced together with their owning
/// subsystems. Cypher equality and ordering are three-valued and are implemented in
/// `graphus-cypher` (FR-QL-8); the derived [`PartialEq`] here is structural and is
/// **not** the Cypher equality operator.
pub mod value {
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
        // Temporal, Point, Node, Relationship, and Path variants are added with
        // their owning subsystems (see specification/04-technical-design.md §7.2).
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
