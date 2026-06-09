//! Three-valued (Kleene) logic for Cypher (`04-technical-design.md` §7.2; openCypher
//! CIP2016-06-14 §Equality and the Cypher 9 specification, which the TCK enforces).
//!
//! Cypher predicates are **three-valued**: a predicate evaluates to `TRUE`, `FALSE`, or `NULL`
//! (the "unknown" value). Boolean connectives follow Kleene's strong three-valued logic, where
//! `NULL` propagates *unless* the other operand already determines the result (e.g. `TRUE OR NULL`
//! is `TRUE` because the first operand alone settles the disjunction).
//!
//! `WHERE` keeps a row only when its predicate is exactly [`Ternary::True`]; both `False` and
//! `Null` reject the row ([`Ternary::is_true`]). This module is deliberately tiny and total — it has
//! no dependency on [`graphus_core::Value`]; the comparison→`Ternary` bridge (e.g.
//! [`crate::equality::equals`] and [`crate::equality::is_in`]) lives in the `equality` module, and
//! the total order in `ordering`.

/// A Cypher truth value: `TRUE`, `FALSE`, or `NULL` (unknown).
///
/// This is the result type of every Cypher predicate. Use [`Ternary::is_true`] for `WHERE`-style
/// row filtering (only `True` keeps a row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum Ternary {
    /// Definitely true.
    True,
    /// Definitely false.
    False,
    /// Unknown — the result of comparing with or against `NULL`.
    Null,
}

impl Ternary {
    /// Lifts a Rust `bool` into a definite [`Ternary`] (`true` → `True`, `false` → `False`).
    pub fn from_bool(b: bool) -> Self {
        if b { Self::True } else { Self::False }
    }

    /// Returns `true` only for [`Ternary::True`]. This is the `WHERE` / predicate-acceptance rule:
    /// a row is kept only when its predicate is `TRUE` — `FALSE` and `NULL` both reject it
    /// (CIP §Equality; Cypher 9 `WHERE` semantics).
    #[must_use]
    pub fn is_true(self) -> bool {
        matches!(self, Self::True)
    }

    /// Returns `true` only for [`Ternary::Null`] (the unknown value).
    #[must_use]
    pub fn is_null(self) -> bool {
        matches!(self, Self::Null)
    }

    /// Kleene logical **AND**.
    ///
    /// `FALSE` dominates (`FALSE AND anything = FALSE`, even `FALSE AND NULL`), because a single
    /// false conjunct settles the result regardless of the unknown. Otherwise `NULL` propagates.
    ///
    /// | AND   | TRUE  | FALSE | NULL  |
    /// |-------|-------|-------|-------|
    /// | TRUE  | TRUE  | FALSE | NULL  |
    /// | FALSE | FALSE | FALSE | FALSE |
    /// | NULL  | NULL  | FALSE | NULL  |
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Null,
        }
    }

    /// Kleene logical **OR**.
    ///
    /// `TRUE` dominates (`TRUE OR anything = TRUE`, even `TRUE OR NULL`), because a single true
    /// disjunct settles the result regardless of the unknown. Otherwise `NULL` propagates.
    ///
    /// | OR    | TRUE  | FALSE | NULL  |
    /// |-------|-------|-------|-------|
    /// | TRUE  | TRUE  | TRUE  | TRUE  |
    /// | FALSE | TRUE  | FALSE | NULL  |
    /// | NULL  | TRUE  | NULL  | NULL  |
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Null,
        }
    }

    /// Logical **XOR** in Kleene logic: `NULL` if either operand is `NULL`, else the boolean XOR.
    ///
    /// Unlike `AND`/`OR`, neither operand value can settle an XOR while the other is unknown, so
    /// `NULL` always propagates (Cypher 9 `XOR` semantics).
    pub fn xor(self, other: Self) -> Self {
        match (self, other) {
            (Self::Null, _) | (_, Self::Null) => Self::Null,
            (a, b) => Self::from_bool(a != b),
        }
    }
}

impl std::ops::Not for Ternary {
    type Output = Self;

    /// Kleene logical **NOT**: `NOT TRUE = FALSE`, `NOT FALSE = TRUE`, `NOT NULL = NULL`.
    ///
    /// Exposed as the [`std::ops::Not`] operator so call sites read `!predicate` or `predicate.not()`
    /// fluently alongside [`Ternary::and`] / [`Ternary::or`] (Cypher 9 `NOT` semantics).
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Null => Self::Null,
        }
    }
}

impl From<bool> for Ternary {
    fn from(b: bool) -> Self {
        Self::from_bool(b)
    }
}

#[cfg(test)]
mod tests {
    use super::Ternary::{False, Null, True};
    use super::*;

    const ALL: [Ternary; 3] = [True, False, Null];

    #[test]
    fn not_truth_table() {
        assert_eq!(!True, False);
        assert_eq!(!False, True);
        assert_eq!(!Null, Null);
    }

    #[test]
    fn and_truth_table_exhaustive() {
        // Row-major over [TRUE, FALSE, NULL] × [TRUE, FALSE, NULL].
        let expected = [
            [True, False, Null],   // TRUE  AND *
            [False, False, False], // FALSE AND *
            [Null, False, Null],   // NULL  AND *
        ];
        for (i, &a) in ALL.iter().enumerate() {
            for (j, &b) in ALL.iter().enumerate() {
                assert_eq!(a.and(b), expected[i][j], "{a:?} AND {b:?}");
            }
        }
    }

    #[test]
    fn or_truth_table_exhaustive() {
        let expected = [
            [True, True, True],  // TRUE  OR *
            [True, False, Null], // FALSE OR *
            [True, Null, Null],  // NULL  OR *
        ];
        for (i, &a) in ALL.iter().enumerate() {
            for (j, &b) in ALL.iter().enumerate() {
                assert_eq!(a.or(b), expected[i][j], "{a:?} OR {b:?}");
            }
        }
    }

    #[test]
    fn xor_truth_table_exhaustive() {
        let expected = [
            [False, True, Null], // TRUE  XOR *
            [True, False, Null], // FALSE XOR *
            [Null, Null, Null],  // NULL  XOR *
        ];
        for (i, &a) in ALL.iter().enumerate() {
            for (j, &b) in ALL.iter().enumerate() {
                assert_eq!(a.xor(b), expected[i][j], "{a:?} XOR {b:?}");
            }
        }
    }

    #[test]
    fn and_or_are_commutative() {
        for &a in &ALL {
            for &b in &ALL {
                assert_eq!(a.and(b), b.and(a), "AND not commutative: {a:?},{b:?}");
                assert_eq!(a.or(b), b.or(a), "OR not commutative: {a:?},{b:?}");
                assert_eq!(a.xor(b), b.xor(a), "XOR not commutative: {a:?},{b:?}");
            }
        }
    }

    #[test]
    fn de_morgan_holds_in_kleene_logic() {
        // NOT(a AND b) == (NOT a) OR (NOT b); NOT(a OR b) == (NOT a) AND (NOT b).
        for &a in &ALL {
            for &b in &ALL {
                assert_eq!(!a.and(b), (!a).or(!b), "De Morgan AND: {a:?},{b:?}");
                assert_eq!(!a.or(b), (!a).and(!b), "De Morgan OR: {a:?},{b:?}");
            }
        }
    }

    #[test]
    fn where_keeps_only_true() {
        assert!(True.is_true());
        assert!(!False.is_true());
        assert!(!Null.is_true()); // NULL rejects the row, same as FALSE
    }

    #[test]
    fn from_bool_roundtrip() {
        assert_eq!(Ternary::from(true), True);
        assert_eq!(Ternary::from(false), False);
    }
}
