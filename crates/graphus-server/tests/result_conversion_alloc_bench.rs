//! Allocation micro-bench for the result-cell → wire-value conversion (rmp #367).
//!
//! The production seams convert every result row by calling [`materialized_to_bolt`] /
//! [`materialized_to_rest`] on each owned cell. Before #367 the conversion **borrowed** the cell and
//! deep-cloned every `String` / label `Vec` / property `(String, Value)` `Vec` into the destination,
//! then dropped the owned cell — a heap clone-then-free per field on every row. #367 made the
//! conversion **consume** the cell and move those owned fields straight into the destination.
//!
//! This bench quantifies that on a property-heavy node row by counting global allocations with a
//! counting allocator, comparing the by-value (current) path against a clone-then-convert path that
//! reproduces the pre-#367 borrow-and-clone cost. `#[ignore]` so it never runs in the normal suite;
//! invoke with `cargo test -p graphus-server --test result_conversion_alloc_bench -- --ignored
//! --nocapture`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use graphus_core::Value;
use graphus_cypher::{MaterializedNode, MaterializedValue};
use graphus_server::engine::bolt_values::materialized_to_bolt;
use graphus_server::engine::rest_values::materialized_to_rest;

/// A process-global allocation counter wrapping the system allocator. Counts every `alloc` call
/// (each `String`/`Vec` heap buffer is one) so we can attribute allocations to a converted region.
struct CountingAlloc;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call verbatim to the system allocator; the only added behavior is a
// relaxed atomic increment on allocation, which has no bearing on allocator soundness.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the wrapped `System` allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` originate from this allocator's `alloc`, forwarded to `System`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Builds a property-heavy node cell: many labels and many string-valued properties, so the
/// per-field clone cost is the dominant signal.
fn heavy_node_cell() -> MaterializedValue {
    let labels: Vec<String> = (0..8).map(|i| format!("Label{i}")).collect();
    let properties: Vec<(String, Value)> = (0..32)
        .map(|i| {
            (
                format!("prop_key_{i}"),
                Value::String(format!("property value number {i}")),
            )
        })
        .collect();
    MaterializedValue::Node(MaterializedNode {
        id: 42,
        labels,
        properties,
    })
}

/// Counts allocations performed while running `f` once.
fn count_allocs<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = ALLOCS.load(Ordering::Relaxed);
    let out = std::hint::black_box(f());
    let after = ALLOCS.load(Ordering::Relaxed);
    (after - before, out)
}

#[test]
#[ignore = "allocation micro-bench; run with --ignored --nocapture"]
fn bolt_conversion_alloc_count() {
    // Pre-build the cells outside the measured region so we only count conversion allocations.
    let cell_new = heavy_node_cell();
    let cell_old = heavy_node_cell();

    // AFTER (#367): by-value move — no per-field clone.
    let (new_allocs, _bolt_new) = count_allocs(|| materialized_to_bolt(cell_new));

    // BEFORE (#367 reproduction): borrow + clone every field, then convert. The explicit clone
    // recreates exactly the per-field heap clones the old `&`-taking conversion performed.
    let (old_allocs, _bolt_old) = count_allocs(|| {
        let cloned = std::hint::black_box(cell_old.clone());
        materialized_to_bolt(cloned)
    });

    println!(
        "[bolt] allocations per property-heavy row — before(clone): {old_allocs}, after(move): {new_allocs}"
    );
    assert!(
        new_allocs < old_allocs,
        "by-value conversion must allocate strictly less than the clone path (before={old_allocs}, after={new_allocs})"
    );
}

#[test]
#[ignore = "allocation micro-bench; run with --ignored --nocapture"]
fn rest_conversion_alloc_count() {
    let cell_new = heavy_node_cell();
    let cell_old = heavy_node_cell();

    let (new_allocs, _rest_new) = count_allocs(|| materialized_to_rest(cell_new));
    let (old_allocs, _rest_old) = count_allocs(|| {
        let cloned = std::hint::black_box(cell_old.clone());
        materialized_to_rest(cloned)
    });

    println!(
        "[rest] allocations per property-heavy row — before(clone): {old_allocs}, after(move): {new_allocs}"
    );
    assert!(
        new_allocs < old_allocs,
        "by-value conversion must allocate strictly less than the clone path (before={old_allocs}, after={new_allocs})"
    );
}
