//! The shared **value-nesting depth bound** (`SEC-190`, CWE-674 / CWE-400).
//!
//! Several total operations over [`Value`] recurse one stack frame per nesting level of the *data*:
//! Cypher equality ([`crate::equality`]), the orderability total order ([`crate::ordering`]), and
//! the structural `PartialEq`/`Hash` the standard library derives on a nested `Value`. The nesting
//! depth of a value is **attacker-controlled** — a query parameter is bound verbatim — so an
//! unbounded recursion is a remote stack-overflow DoS: on stable Rust a stack overflow is an
//! *unrecoverable process abort* (SIGABRT), not a catchable panic.
//!
//! The defence is layered:
//!
//! 1. **At the trust boundary.** [`crate::binding::bind_parameters`] rejects any parameter whose
//!    value nests deeper than [`MAX_VALUE_DEPTH`] with a typed, recoverable
//!    [`BindError`](crate::binding::BindError) — *before* the value ever reaches the engine, so deep
//!    *supplied* data never enters the pipeline.
//! 2. **At runtime materialisation (`SEC-190`, rmp #589).** A value can also be built *inside* the
//!    engine deeper than any parameter: a self-referential projection chain (`WITH [a] AS a` /
//!    `WITH collect(a) AS a`, one nesting level added per clause, with no clause-count limit) grows a
//!    runtime value unboundedly deep from a shallow query. The parameter guard cannot see these. So
//!    every point that **materialises or rebinds** a runtime value — each `WITH`/`RETURN` projection
//!    ([`crate::executor::project_row`] via [`rowvalue_depth_exceeds`]) and each `collect` gather —
//!    additionally caps the depth, rejecting past [`MAX_VALUE_DEPTH`] with a recoverable
//!    [`EvalError::ResourceLimit`](crate::eval::EvalError::ResourceLimit). A rejected query fails
//!    cleanly; the connection and every other database the server hosts stay up.
//! 3. **Defence in depth.** The comparison routines cap their own recursion at [`MAX_VALUE_DEPTH`],
//!    and the wire encoders (Bolt `pack_value`, REST Jolt/CBOR) cap theirs, so even a value that
//!    somehow slipped past the materialisation guards can never overflow the stack on the output
//!    path (or a small worker stack's recursive `Drop`).
//!
//! Why iterative? On stable Rust a stack overflow is an **unrecoverable process abort** (SIGABRT),
//! not a catchable panic — [`std::panic::catch_unwind`] cannot save the process, so it would take
//! down every database and connection the server hosts. The depth *measurement* must therefore never
//! itself recurse the (attacker-controlled) depth; both [`depth_exceeds`] and [`rowvalue_depth_exceeds`]
//! walk an explicit work stack and bail the instant the cap is passed, in `O(limit)` work.
//!
//! [`MAX_VALUE_DEPTH`] is far above any legitimate Cypher value (real lists/maps nest a handful of
//! levels), so no layer affects conforming queries or the TCK.

use crate::runtime::RowValue;
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

/// The [`RowValue`] analogue of [`depth_exceeds`]: returns `true` as soon as the walk proves `rv`
/// nests deeper than `limit`, in `O(limit)` work, **without recursing**.
///
/// [`RowValue`] is a superset of [`Value`] (it additionally carries structural node / relationship /
/// path bindings and structural list/map spines), and a runtime value may mix the two layers — e.g.
/// [`RowValue::list`](crate::runtime::RowValue::list) collapses a pure-property list into
/// `RowValue::Value(Value::List(..))`, so nesting can straddle the `RowValue` spine and the inner
/// `Value` spine. This walk descends **both**: the `RowValue::Value` wrapper is *not* itself a
/// nesting level (it is only a tag), so a `RowValue::Value(v)` is measured at the same depth as `v`,
/// keeping the depth of a pure-property value identical to what [`depth_exceeds`] reports for it.
/// Structural leaves (`Node`/`Rel`/`Path`) have no nested value children (they collapse to a scalar
/// in a value context), so they terminate a branch.
///
/// Used at every runtime materialisation point (`SEC-190`, rmp #589) to reject an over-deep value
/// *before* it can reach a depth-recursive consumer — value collapse
/// ([`to_value`](crate::eval::to_value)), the wire encoders, or the derived recursive `Drop`.
#[must_use]
pub fn rowvalue_depth_exceeds(rv: &RowValue, limit: usize) -> bool {
    // A work item is either a `RowValue` node or an inner `Value` node, each tagged with its depth.
    enum Node<'a> {
        Rv(&'a RowValue),
        Val(&'a Value),
    }
    let mut work: Vec<(Node<'_>, usize)> = vec![(Node::Rv(rv), 0)];
    while let Some((node, d)) = work.pop() {
        if d > limit {
            return true;
        }
        match node {
            // The `RowValue::Value` wrapper is a tag, not a nesting level: descend at the same depth.
            Node::Rv(RowValue::Value(v)) => work.push((Node::Val(v), d)),
            Node::Rv(RowValue::List(items)) => {
                for item in items {
                    work.push((Node::Rv(item), d + 1));
                }
            }
            Node::Rv(RowValue::Map(entries)) => {
                for (_, val) in entries {
                    work.push((Node::Rv(val), d + 1));
                }
            }
            // A structural entity/path binding collapses to a scalar in a value context — a leaf here.
            Node::Rv(RowValue::Node(_) | RowValue::Rel(_) | RowValue::Path(_)) => {}
            Node::Val(Value::List(items)) => {
                for item in items {
                    work.push((Node::Val(item), d + 1));
                }
            }
            Node::Val(Value::Map(entries)) => {
                for (_, val) in entries {
                    work.push((Node::Val(val), d + 1));
                }
            }
            // Scalars (including temporals, points, bytes) have no nested `Value` children.
            Node::Val(_) => {}
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

    // ---- rowvalue_depth_exceeds -------------------------------------------------------------

    /// Builds a `RowValue` nested `depth` levels through the **structural** `RowValue::List` spine
    /// (each element a nested list containing a single structural node binding, so the collapse in
    /// [`RowValue::list`](crate::runtime::RowValue::list) keeps it structural — the case a pure
    /// `Value` walk cannot represent).
    fn nest_structural(depth: usize) -> RowValue {
        // A bare node id keeps the innermost element structural, so every wrapping list stays a
        // `RowValue::List` rather than collapsing to `RowValue::Value(Value::List)`.
        let mut rv = RowValue::Node(crate::runtime::NodeRef {
            id: crate::graph_access::NodeId(0),
        });
        for _ in 0..depth {
            rv = RowValue::List(vec![rv]);
        }
        rv
    }

    #[test]
    fn rowvalue_scalar_has_depth_zero() {
        assert!(!rowvalue_depth_exceeds(
            &RowValue::Value(Value::Integer(1)),
            0
        ));
    }

    #[test]
    fn rowvalue_value_wrapper_is_not_a_level() {
        // A pure-property value carried as `RowValue::Value(..)` must measure identically to the bare
        // `Value` (the wrapper is a tag, not a nesting level).
        let v = nest(3);
        let rv = RowValue::Value(v.clone());
        for cap in 0..5 {
            assert_eq!(
                depth_exceeds(&v, cap),
                rowvalue_depth_exceeds(&rv, cap),
                "cap {cap}"
            );
        }
    }

    #[test]
    fn rowvalue_structural_spine_counts_and_is_iterative() {
        // A structural `RowValue::List` spine nests just like a property list, and a spine far deeper
        // than the cap is detected without recursing (never overflows the measuring stack).
        let at_cap = nest_structural(MAX_VALUE_DEPTH);
        assert!(!rowvalue_depth_exceeds(&at_cap, MAX_VALUE_DEPTH));
        let over = nest_structural(MAX_VALUE_DEPTH + 50);
        assert!(rowvalue_depth_exceeds(&over, MAX_VALUE_DEPTH));
    }

    #[test]
    fn rowvalue_mixed_spine_straddles_both_layers() {
        // A structural list whose leaf is a *property* nested value: total depth spans the structural
        // `RowValue::List` layer and the inner `Value::List` layer.
        let inner = RowValue::Value(nest(2)); // Value depth 2
        let rv = RowValue::List(vec![RowValue::List(vec![inner])]); // + 2 structural levels = depth 4
        assert!(!rowvalue_depth_exceeds(&rv, 4));
        assert!(rowvalue_depth_exceeds(&rv, 3));
    }
}
