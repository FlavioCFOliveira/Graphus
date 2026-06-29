//! The per-value **materialised-size budget** (`SEC-191` family, CWE-770 / CWE-789).
//!
//! `range()` already refuses to materialise a list bigger than [`crate::eval`]'s `MAX_RANGE_BYTES`
//! (256 MiB) — it rejects the request with a typed runtime error *before* allocating. Every other
//! value builder, however, had **no** per-value memory budget: a single `collect(...)` over a huge
//! stream, a runaway `+`/`replace` string, or a list concatenation could each grow a **single
//! materialised value** until it exhausts the per-database engine thread's heap. A patient client can
//! therefore drive one query to OOM the whole server (every database the engine hosts dies with it),
//! bounded only by total RAM — a memory-exhaustion DoS the per-statement timeout (`rmp` #476) only
//! partially mitigates (a 2-minute allocation can OOM first).
//!
//! This module is the shared budget those builders enforce. [`MAX_VALUE_BYTES`] is the default
//! ceiling (the **same** 256 MiB `range()` uses, so the two limits can never diverge), and the
//! estimators give a cheap, **incremental** byte cost so a builder can reject a value the instant the
//! running total crosses the budget — never allocating the over-budget value at all.
//!
//! ## Configurable ceiling
//!
//! The effective ceiling is read through [`max_value_bytes`], which returns [`MAX_VALUE_BYTES`] unless
//! a process-wide override is installed via [`set_max_value_bytes`] / [`BudgetOverride`]. Production
//! and the openCypher TCK run at the 256 MiB default; the override exists so the regression suite can
//! lower the ceiling to a few KiB and **measure** the boundary (reject just above, accept just below)
//! for every vector — including the morsel-parallel `collect` path — without allocating 256 MiB per
//! test. The override is a single `Relaxed` atomic load on the builder paths (negligible).
//!
//! ## Cost model (deliberately conservative)
//!
//! [`estimate_value_bytes`] / [`estimate_rowvalue_bytes`] approximate the in-memory footprint of a
//! value: a fixed per-node base (the enum slot) plus the heap a `String` / `Bytes` / `List` / `Map`
//! directly owns. They walk a value **once, iteratively** (an explicit work stack, never recursion,
//! so estimating can no more overflow the stack than [`crate::value_depth`] can), and short-circuit
//! the moment the running total exceeds the ceiling — a pathologically large value is detected in
//! `O(budget)` work, never `O(value)`. The estimate may slightly **over**-count nested structure
//! (each level re-adds the base); that only ever tightens the effective budget, which is the safe
//! direction for a DoS guard and is still vastly above any legitimate Cypher value.
//!
//! ## How builders use it (amortised `O(1)`)
//!
//! A *streaming* builder (`collect`, list/pattern comprehensions) keeps a running byte total and adds
//! the estimate of **each appended element** as it is pushed — walking only the new element, so the
//! total work is `O(total bytes)` (amortised `O(1)` per appended byte), never re-walking the
//! accumulated structure. A *concatenating* builder (`+` on lists) caps on the result **element
//! count** via [`max_list_elements`] — an `O(1)` check mirroring `range()`'s element ceiling — and a
//! *string* builder caps on the result **byte length**, both computed without allocating the result.

use std::sync::atomic::{AtomicUsize, Ordering};

use graphus_core::Value;

use crate::runtime::RowValue;

/// The **default** byte budget a single materialised value may occupy (`SEC-191`, CWE-770 /
/// CWE-789).
///
/// Equal to `MAX_RANGE_BYTES` (`crate::eval`): one ceiling for every per-value materialisation, so a
/// `collect`, a string concatenation, a list build and a `range()` can never disagree on what counts
/// as "too large". 256 MiB is a generous single value — far beyond any legitimate Cypher query or the
/// openCypher TCK, which build values nesting a handful of levels and counting at most a few thousand
/// elements — yet small enough that a single such value cannot exhaust a normal host's RAM.
pub const MAX_VALUE_BYTES: usize = 256 * 1024 * 1024;

/// The live per-value budget. [`MAX_VALUE_BYTES`] unless a test/runtime override is installed via
/// [`set_max_value_bytes`]. A `Relaxed` atomic: the value is a single advisory threshold, never a
/// synchronisation point, so no ordering beyond atomicity is required.
static VALUE_BUDGET_BYTES: AtomicUsize = AtomicUsize::new(MAX_VALUE_BYTES);

/// The fixed per-node cost: the in-memory size of one [`Value`] enum slot. A list/map of `n` elements
/// owns at least `n` of these in its backing `Vec`, so this is the dominant cost of the
/// element-count-driven vectors (`collect` of scalars, list `+`).
const NODE_BASE: usize = std::mem::size_of::<Value>();

/// The effective per-value byte budget every value builder enforces (`SEC-191`): [`MAX_VALUE_BYTES`]
/// unless overridden by [`set_max_value_bytes`].
#[must_use]
#[inline]
pub fn max_value_bytes() -> usize {
    VALUE_BUDGET_BYTES.load(Ordering::Relaxed)
}

/// Installs a new effective per-value budget and returns the previous one. Intended for the
/// regression suite (to lower the ceiling and measure the boundary cheaply) and for any future
/// server-level configuration of the limit. Prefer [`BudgetOverride`] in tests so the previous value
/// is restored even on panic.
pub fn set_max_value_bytes(bytes: usize) -> usize {
    VALUE_BUDGET_BYTES.swap(bytes.max(1), Ordering::Relaxed)
}

/// An RAII guard that lowers (or raises) the per-value budget for the duration of a scope and
/// restores the previous value on drop — including on unwind. Process-global: a test that installs
/// one must hold whatever lock serialises the other budget-sensitive tests in its binary.
#[must_use = "the override is reverted as soon as the guard is dropped"]
pub struct BudgetOverride {
    previous: usize,
}

impl BudgetOverride {
    /// Sets the effective budget to `bytes` until the returned guard drops.
    pub fn new(bytes: usize) -> Self {
        Self {
            previous: set_max_value_bytes(bytes),
        }
    }
}

impl Drop for BudgetOverride {
    fn drop(&mut self) {
        set_max_value_bytes(self.previous);
    }
}

/// The largest number of elements a concatenation-built list may hold, derived from the live budget
/// ([`max_value_bytes`]) and [`NODE_BASE`] exactly as `range()` derives its element ceiling — so the
/// `O(1)` element-count guard the list `+` builders use and the byte budget it stands in for can
/// never diverge.
#[must_use]
pub fn max_list_elements() -> usize {
    // `NODE_BASE` is always > 0 (a `Value` is never zero-sized); `.max(1)` keeps the division total.
    max_value_bytes() / NODE_BASE.max(1)
}

/// An approximate in-memory byte cost of a property [`Value`], walked **once, iteratively** and
/// short-circuited the moment it exceeds the live budget.
///
/// Used to bound a single materialised value against the budget without ever allocating an
/// over-budget value. See the [module docs](self) for the cost model and why the estimate is
/// deliberately conservative.
#[must_use]
pub fn estimate_value_bytes(v: &Value) -> usize {
    let cap = max_value_bytes();
    let mut total: usize = 0;
    let mut stack: Vec<&Value> = vec![v];
    while let Some(node) = stack.pop() {
        total = total.saturating_add(NODE_BASE);
        match node {
            Value::String(s) => total = total.saturating_add(s.len()),
            Value::Bytes(b) => total = total.saturating_add(b.len()),
            Value::List(items) => stack.extend(items.iter()),
            Value::Map(entries) => {
                for (k, val) in entries {
                    total = total.saturating_add(k.len());
                    stack.push(val);
                }
            }
            // Scalars (numbers, booleans, temporals, points, the boxed zoned date-time) own no further
            // heap a budget needs to count beyond their enum slot.
            _ => {}
        }
        // Once the value is proven over budget there is no point walking the rest of it.
        if total > cap {
            break;
        }
    }
    total
}

/// An approximate in-memory byte cost of a [`RowValue`] (the structural superset of [`Value`] that
/// carries node / relationship / path references), walked **once, iteratively** and short-circuited
/// at the live budget.
///
/// This is the estimator the streaming builders (`collect`, comprehensions) accumulate per appended
/// element, since those preserve structural entity references. Entity references count only their
/// fixed enum-slot footprint (an id), which is exactly the dominant cost of a `collect(n)` over many
/// nodes.
#[must_use]
pub fn estimate_rowvalue_bytes(rv: &RowValue) -> usize {
    let cap = max_value_bytes();
    let mut total: usize = 0;
    let mut stack: Vec<&RowValue> = vec![rv];
    while let Some(node) = stack.pop() {
        total = total.saturating_add(NODE_BASE);
        match node {
            RowValue::Value(v) => total = total.saturating_add(estimate_value_bytes(v)),
            // A node / relationship reference is an id; its enum slot (the base above) covers it.
            RowValue::Node(_) | RowValue::Rel(_) => {}
            // A path owns one slot per hop in its `steps` Vec.
            RowValue::Path(p) => {
                total = total.saturating_add(p.steps.len().saturating_mul(NODE_BASE));
            }
            RowValue::List(items) => stack.extend(items.iter()),
            RowValue::Map(entries) => {
                for (k, val) in entries {
                    total = total.saturating_add(k.len());
                    stack.push(val);
                }
            }
        }
        if total > cap {
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_is_cheap_and_string_counts_its_bytes() {
        assert_eq!(estimate_value_bytes(&Value::Integer(7)), NODE_BASE);
        let s = "x".repeat(1000);
        assert_eq!(
            estimate_value_bytes(&Value::String(s)),
            NODE_BASE.saturating_add(1000)
        );
    }

    #[test]
    fn list_counts_each_element() {
        let list = Value::List(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]);
        // Outer list slot + three element slots.
        assert_eq!(estimate_value_bytes(&list), NODE_BASE.saturating_mul(4));
    }

    #[test]
    fn over_budget_value_short_circuits_without_full_walk() {
        // A list far over the element ceiling is detected as over budget; the estimate stops early
        // (it never needs to visit every element), so it just has to report a value > the budget.
        let huge = Value::List(vec![Value::Integer(0); max_list_elements() + 1_000]);
        assert!(estimate_value_bytes(&huge) > MAX_VALUE_BYTES);
    }

    #[test]
    fn rowvalue_string_matches_value_string() {
        let s = "abc".repeat(64);
        let rv = RowValue::Value(Value::String(s.clone()));
        // The RowValue wrapper adds one base slot on top of the inner Value estimate.
        assert_eq!(
            estimate_rowvalue_bytes(&rv),
            NODE_BASE.saturating_add(estimate_value_bytes(&Value::String(s)))
        );
    }

    #[test]
    fn default_budget_is_the_const() {
        // No override installed in this (lib) test binary: the live budget is the 256 MiB default.
        assert_eq!(max_value_bytes(), MAX_VALUE_BYTES);
        let limit = max_list_elements();
        assert!(limit > 0);
        assert!(limit.saturating_mul(NODE_BASE) <= MAX_VALUE_BYTES);
    }
}
