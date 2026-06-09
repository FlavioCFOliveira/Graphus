//! Node label-set encoding in the frozen `NodeRecord.labels` `u64` (`05-storage-format.md` §9;
//! `rmp` task #42 — node labels).
//!
//! `05 §9` froze the node record's `labels` field as an *"inline label-set reference: small sets
//! bit-packed; large sets → token-list block id"*. This module implements the **bit-packed
//! small-set** case (task #42); the token-list overflow block is a separate follow-up
//! (`rmp` task #39, alongside index-accelerated label scans, the string/list property overflow
//! heap, and MVCC concurrency).
//!
//! # The bitmap scheme
//!
//! A node's label set is encoded as a [`Label`](crate::tokens::Namespace::Label)-namespace
//! **token-id bitmap**: bit `i` of the `u64` is set **iff** the node carries the label whose
//! `Label`-namespace token id is `i`, for `i` in `0..=62`. Bit **63** is the **overflow flag**.
//!
//! ```text
//!  bit:  63   62  61  …   2   1   0
//!       [OF] [ token ids 62 … 0 (set membership) ]
//! ```
//!
//! Token ids are dense and assigned monotonically from `0` within the `Label` namespace
//! ([`crate::tokens`]), so the first 63 distinct labels created in a store map to bits `0..=62` and
//! are representable inline. A node that would need a label whose token id is **≥ 63** (i.e. the
//! 64th-or-later distinct label ever interned) cannot be represented by this 63-bit inline set; that
//! is the **overflow** case.
//!
//! # Overflow is a clear, documented deferred error (task #42 boundary)
//!
//! When the token-list overflow block (#39) is not built, an operation that would need a label token
//! id `≥ 63` (or a set of more than 63 labels) returns [`LabelError::Overflow`] — a clear, documented
//! error, **never** a silently wrong or partial result. The [`OVERFLOW_BIT`] is reserved so the
//! follow-up can flip it to mean "the real set lives in a token-list block referenced by the
//! remaining bits"; this build never *sets* it (every value it writes has it clear) and treats a node
//! whose record *reads* it set as overflowed (a state only a future #39 build can legitimately
//! create).
//!
//! # Determinism
//!
//! [`token_ids`] returns the set in ascending token-id order, so a node's label token ids — and
//! hence the names a caller maps them to — are enumerated deterministically.

use std::fmt;

/// Bit index of the overflow flag in the `labels` `u64` (`05 §9`).
///
/// Reserved for the token-list overflow block (#39): when set, the small-set interpretation of the
/// other bits does **not** apply. This build never sets it and rejects label token ids `≥ 63`
/// ([`MAX_INLINE_LABEL_ID`] is the largest inline id) with [`LabelError::Overflow`].
pub const OVERFLOW_BIT: u32 = 63;

/// The largest `Label`-namespace token id representable in the inline bitmap (bits `0..=62`).
///
/// A token id strictly greater than this needs the overflow block (#39); operations on it return
/// [`LabelError::Overflow`].
pub const MAX_INLINE_LABEL_ID: u32 = 62;

/// The overflow flag as a mask over the `labels` `u64`.
const OVERFLOW_MASK: u64 = 1u64 << OVERFLOW_BIT;
/// Mask of the 63 inline membership bits (`0..=62`), i.e. everything except [`OVERFLOW_MASK`].
const INLINE_MASK: u64 = !OVERFLOW_MASK;

/// The reason a label-bitmap operation could not be carried out by this build.
///
/// Both arms describe the **deferred** overflow case (`rmp` task #39): the token-list overflow block
/// that would hold a label set too large for the 63-bit inline bitmap is not built in task #42. A
/// caller surfaces this as a clear runtime error rather than producing a wrong or partial result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LabelError {
    /// A label's `Label`-namespace token id is `≥ 63` ([`MAX_INLINE_LABEL_ID`] is the largest inline
    /// id), so it does not fit the inline bitmap and needs the overflow block (#39).
    Overflow {
        /// The offending label token id (`≥ 63`).
        token_id: u32,
    },
    /// The node's stored `labels` bitmap already has the [`OVERFLOW_BIT`] set, i.e. its real label
    /// set lives in a token-list overflow block this build cannot read (#39). Encountered only on
    /// data a future #39 build wrote; this build never sets the bit.
    OverflowFlagSet,
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow { token_id } => write!(
                f,
                "label token id {token_id} exceeds the {MAX_INLINE_LABEL_ID}-bit inline label \
                 bitmap: a node with more than {} distinct labels (or a label interned beyond the \
                 inline range) needs the token-list overflow block, which is a follow-up \
                 (graphus #39)",
                MAX_INLINE_LABEL_ID + 1
            ),
            Self::OverflowFlagSet => write!(
                f,
                "node label set is in overflow form (the inline bitmap's overflow flag is set): its \
                 labels live in a token-list overflow block this build cannot read (a follow-up, \
                 graphus #39)"
            ),
        }
    }
}

impl std::error::Error for LabelError {}

impl From<LabelError> for graphus_core::error::GraphusError {
    /// A label overflow is surfaced as a **runtime** error: the query/operation is well-formed, but
    /// the label set it needs exceeds this build's inline-bitmap storage capability (#39).
    fn from(e: LabelError) -> Self {
        graphus_core::error::GraphusError::Runtime(e.to_string())
    }
}

/// The bit mask for an inline label token id.
///
/// # Errors
/// Returns [`LabelError::Overflow`] if `token_id > MAX_INLINE_LABEL_ID` (it would collide with the
/// overflow flag or fall outside the 63-bit inline range).
fn bit_mask(token_id: u32) -> Result<u64, LabelError> {
    if token_id > MAX_INLINE_LABEL_ID {
        return Err(LabelError::Overflow { token_id });
    }
    Ok(1u64 << token_id)
}

/// Whether `labels`'s overflow flag is set (its set lives in a #39 token-list block).
#[must_use]
pub fn is_overflowed(labels: u64) -> bool {
    labels & OVERFLOW_MASK != 0
}

/// Whether the node whose bitmap is `labels` carries the label with `token_id`.
///
/// # Errors
/// - [`LabelError::OverflowFlagSet`] if `labels` is in overflow form (the inline bits are not the
///   authoritative set; #39 owns that case).
/// - [`LabelError::Overflow`] if `token_id` is outside the inline range, since this build can never
///   have set such a bit (asking is itself an overflow query).
pub fn has_label(labels: u64, token_id: u32) -> Result<bool, LabelError> {
    if is_overflowed(labels) {
        return Err(LabelError::OverflowFlagSet);
    }
    Ok(labels & bit_mask(token_id)? != 0)
}

/// The ascending list of `Label`-namespace token ids set in `labels`.
///
/// # Errors
/// Returns [`LabelError::OverflowFlagSet`] if `labels` is in overflow form (#39); the inline bits do
/// not enumerate the real set in that case.
pub fn token_ids(labels: u64) -> Result<Vec<u32>, LabelError> {
    if is_overflowed(labels) {
        return Err(LabelError::OverflowFlagSet);
    }
    let mut bits = labels & INLINE_MASK;
    let mut out = Vec::with_capacity(bits.count_ones() as usize);
    while bits != 0 {
        let id = bits.trailing_zeros();
        out.push(id);
        bits &= bits - 1; // clear the lowest set bit
    }
    Ok(out)
}

/// Returns `labels` with the bit for `token_id` set (idempotent).
///
/// # Errors
/// - [`LabelError::OverflowFlagSet`] if `labels` is already in overflow form (#39).
/// - [`LabelError::Overflow`] if `token_id` exceeds the inline range and would need the overflow
///   block (#39).
pub fn with_label(labels: u64, token_id: u32) -> Result<u64, LabelError> {
    if is_overflowed(labels) {
        return Err(LabelError::OverflowFlagSet);
    }
    Ok(labels | bit_mask(token_id)?)
}

/// Returns `labels` with the bit for `token_id` cleared (idempotent: clearing an absent label is a
/// no-op).
///
/// # Errors
/// - [`LabelError::OverflowFlagSet`] if `labels` is in overflow form (#39).
/// - [`LabelError::Overflow`] if `token_id` exceeds the inline range (this build cannot have set such
///   a bit, so removing it is an overflow query).
pub fn without_label(labels: u64, token_id: u32) -> Result<u64, LabelError> {
    if is_overflowed(labels) {
        return Err(LabelError::OverflowFlagSet);
    }
    Ok(labels & !bit_mask(token_id)?)
}

/// Builds an inline `labels` bitmap from a set of `Label`-namespace token ids (the exact set,
/// replacing any prior membership). Duplicate ids are idempotent.
///
/// # Errors
/// Returns [`LabelError::Overflow`] for the first `token_id` that exceeds the inline range (#39).
pub fn encode_set(token_ids: &[u32]) -> Result<u64, LabelError> {
    let mut labels = 0u64;
    for &id in token_ids {
        labels |= bit_mask(id)?;
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bitmap_has_no_labels() {
        assert_eq!(token_ids(0).unwrap(), Vec::<u32>::new());
        assert!(!has_label(0, 0).unwrap());
        assert!(!has_label(0, MAX_INLINE_LABEL_ID).unwrap());
        assert!(!is_overflowed(0));
    }

    #[test]
    fn set_get_remove_round_trip() {
        let m = with_label(0, 0).unwrap();
        let m = with_label(m, 5).unwrap();
        let m = with_label(m, MAX_INLINE_LABEL_ID).unwrap();
        assert!(has_label(m, 0).unwrap());
        assert!(has_label(m, 5).unwrap());
        assert!(has_label(m, MAX_INLINE_LABEL_ID).unwrap());
        assert!(!has_label(m, 1).unwrap());
        assert_eq!(token_ids(m).unwrap(), vec![0, 5, MAX_INLINE_LABEL_ID]);

        let m = without_label(m, 5).unwrap();
        assert!(!has_label(m, 5).unwrap());
        assert_eq!(token_ids(m).unwrap(), vec![0, MAX_INLINE_LABEL_ID]);
    }

    #[test]
    fn setting_and_clearing_are_idempotent() {
        let once = with_label(0, 7).unwrap();
        assert_eq!(with_label(once, 7).unwrap(), once);
        let gone = without_label(once, 7).unwrap();
        assert_eq!(without_label(gone, 7).unwrap(), gone);
        // Removing an absent label is a no-op (returns the input unchanged).
        assert_eq!(without_label(0, 3).unwrap(), 0);
    }

    #[test]
    fn encode_set_builds_the_exact_inline_membership() {
        let m = encode_set(&[1, 1, 4, 4, 9]).unwrap();
        assert_eq!(token_ids(m).unwrap(), vec![1, 4, 9]);
    }

    #[test]
    fn token_ids_are_ascending() {
        let m = encode_set(&[62, 0, 31, 1]).unwrap();
        assert_eq!(token_ids(m).unwrap(), vec![0, 1, 31, 62]);
    }

    #[test]
    fn token_id_at_or_above_63_overflows() {
        assert_eq!(
            with_label(0, 63),
            Err(LabelError::Overflow { token_id: 63 })
        );
        assert_eq!(
            with_label(0, 1000),
            Err(LabelError::Overflow { token_id: 1000 })
        );
        assert_eq!(
            encode_set(&[0, 63]),
            Err(LabelError::Overflow { token_id: 63 })
        );
        // Querying / removing an overflowing id is also an overflow (we can never have set it).
        assert_eq!(has_label(0, 63), Err(LabelError::Overflow { token_id: 63 }));
        assert_eq!(
            without_label(0, 63),
            Err(LabelError::Overflow { token_id: 63 })
        );
    }

    #[test]
    fn the_overflow_flag_never_collides_with_an_inline_id() {
        // The maximal inline set (all 63 bits) must leave the overflow flag clear.
        let all: Vec<u32> = (0..=MAX_INLINE_LABEL_ID).collect();
        let m = encode_set(&all).unwrap();
        assert!(
            !is_overflowed(m),
            "63 inline labels must not set the overflow flag"
        );
        assert_eq!(m, INLINE_MASK);
        assert_eq!(token_ids(m).unwrap().len(), 63);
    }

    #[test]
    fn an_overflow_flagged_bitmap_is_an_error_not_a_silent_inline_read() {
        // A bitmap a future #39 build wrote: overflow flag set, with some payload in the low bits.
        let overflowed = OVERFLOW_MASK | 0b1010;
        assert!(is_overflowed(overflowed));
        assert_eq!(token_ids(overflowed), Err(LabelError::OverflowFlagSet));
        assert_eq!(has_label(overflowed, 1), Err(LabelError::OverflowFlagSet));
        assert_eq!(with_label(overflowed, 1), Err(LabelError::OverflowFlagSet));
        assert_eq!(
            without_label(overflowed, 1),
            Err(LabelError::OverflowFlagSet)
        );
    }

    #[test]
    fn label_error_is_a_runtime_graphus_error_mentioning_39() {
        let e: graphus_core::error::GraphusError = LabelError::Overflow { token_id: 63 }.into();
        assert!(matches!(e, graphus_core::error::GraphusError::Runtime(_)));
        assert!(e.to_string().contains("#39"));
        let e2: graphus_core::error::GraphusError = LabelError::OverflowFlagSet.into();
        assert!(e2.to_string().contains("#39"));
    }
}
