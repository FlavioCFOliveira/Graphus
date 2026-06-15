//! The shared **value-nesting depth bound** (`SEC-190`, CWE-674 / CWE-400).
//!
//! Several total operations over [`Value`] recurse one stack frame per nesting level of the *data*:
//! Cypher equality ([`crate::equality`]), the orderability total order ([`crate::ordering`]), and
//! the structural `PartialEq`/`Hash` the standard library derives on a nested `Value`. The nesting
//! depth of a value is **attacker-controlled** — a query parameter is bound verbatim — so an
//! unbounded recursion is a remote stack-overflow DoS: on stable Rust a stack overflow is an
//! *unrecoverable process abort* (SIGABRT), not a catchable panic.
//!
//! The defence is two-layered:
//!
//! 1. **At the trust boundary.** [`crate::binding::bind_parameters`] rejects any parameter whose
//!    value nests deeper than [`MAX_VALUE_DEPTH`] with a typed, recoverable
//!    [`BindError`](crate::binding::BindError) — *before* the value ever reaches the engine. This is
//!    the primary fix: deep data never enters the pipeline.
//! 2. **Defence in depth.** The comparison routines additionally cap their own recursion at
//!    [`MAX_VALUE_DEPTH`], returning a defined, total result past the cap rather than recursing. So
//!    even a value constructed *internally* (not via a parameter) can never overflow the stack.
//!
//! [`MAX_VALUE_DEPTH`] is far above any legitimate Cypher value (real lists/maps nest a handful of
//! levels), so neither layer affects conforming queries or the TCK.

use graphus_core::Value;

/// The maximum nesting depth a [`Value`] may have anywhere it is compared, ordered, hashed, or
/// bound as a parameter.
///
/// Chosen generously relative to any real query (Cypher values nest a handful of levels) yet far
/// below what overflows a worker stack: at this depth the depth-check itself is iterative and the
/// bounded recursion needs only `MAX_VALUE_DEPTH` frames, comfortably inside a default ≥1 MiB stack.
pub const MAX_VALUE_DEPTH: usize = 1_000;

/// Returns the nesting depth of `value` **capped at `limit + 1`** — i.e. as soon as the walk proves
/// the value is deeper than `limit` it stops and reports `limit + 1`, so a pathologically deep value
/// is detected in `O(limit)` work without ever recursing the full depth.
///
/// A scalar has depth `0`; `[1]` has depth `1`; `[[1]]` has depth `2`; a map counts its values.
/// The walk is **iterative** (an explicit work stack), so measuring the depth can never itself
/// overflow the call stack — the whole point of the guard.
#[must_use]
pub fn depth_exceeds(value: &Value, limit: usize) -> bool {
    // Each stack entry is (node, depth_of_node). We push children at depth+1 and bail the instant a
    // node is seen beyond `limit`.
    let mut work: Vec<(&Value, usize)> = vec![(value, 0)];
    while let Some((v, d)) = work.pop() {
        if d > limit {
            return true;
        }
        match v {
            Value::List(items) => {
                for item in items {
                    work.push((item, d + 1));
                }
            }
            Value::Map(entries) => {
                for (_, val) in entries {
                    work.push((val, d + 1));
                }
            }
            // Scalars (including temporals, points, bytes) have no nested `Value` children.
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nest(depth: usize) -> Value {
        let mut v = Value::Integer(0);
        for _ in 0..depth {
            v = Value::List(vec![v]);
        }
        v
    }

    #[test]
    fn scalar_has_depth_zero() {
        assert!(!depth_exceeds(&Value::Integer(1), 0));
    }

    #[test]
    fn detects_over_deep_value_iteratively() {
        // A value far deeper than the cap is detected without recursing (and without overflowing —
        // the measurement is iterative).
        let v = nest(MAX_VALUE_DEPTH + 50);
        assert!(depth_exceeds(&v, MAX_VALUE_DEPTH));
    }

    #[test]
    fn accepts_a_value_at_the_cap() {
        let v = nest(MAX_VALUE_DEPTH);
        assert!(!depth_exceeds(&v, MAX_VALUE_DEPTH));
        let too_deep = nest(MAX_VALUE_DEPTH + 1);
        assert!(depth_exceeds(&too_deep, MAX_VALUE_DEPTH));
    }

    #[test]
    fn map_nesting_counts() {
        let v = Value::Map(vec![("k".to_owned(), Value::List(vec![Value::Integer(1)]))]);
        // map(1) -> list(2) -> int : depth 2, under a cap of 2.
        assert!(!depth_exceeds(&v, 2));
        assert!(depth_exceeds(&v, 1));
    }
}
