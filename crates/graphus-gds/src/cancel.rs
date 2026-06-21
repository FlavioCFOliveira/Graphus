//! Cooperative cancellation plumbing shared by the iterative algorithms.
//!
//! Long-running algorithms periodically call a caller-supplied predicate; when it returns `true`
//! they stop early with [`GdsError::Cancelled`]. This lets a server abort a runaway computation
//! (timeout, client disconnect, shutdown) without `unsafe`, threads, or signals.

use crate::error::GdsError;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cooperative cancellation check.
///
/// Two ready-made constructors cover the common cases: [`Cancel::never`] (no cancellation) and
/// [`Cancel::flag`] (an [`AtomicBool`] flipped by another thread). Any `Fn() -> bool` works via
/// [`Cancel::from_fn`].
pub struct Cancel<'a> {
    // `Send + Sync` so a single `&Cancel` can be shared across the data-parallel (rayon) source
    // loops in the centrality algorithms. Both ready-made constructors are trivially `Send + Sync`
    // (a no-op closure; an `&AtomicBool` load), and `from_fn` requires the predicate to be too.
    check: Box<dyn Fn() -> bool + Send + Sync + 'a>,
}

impl<'a> Cancel<'a> {
    /// A check that never cancels.
    #[must_use]
    pub fn never() -> Self {
        Self {
            check: Box::new(|| false),
        }
    }

    /// A check driven by an [`AtomicBool`]; cancellation is requested when it reads `true`
    /// (`Relaxed` ordering is sufficient — we only need eventual visibility of a one-way flip).
    #[must_use]
    pub fn flag(flag: &'a AtomicBool) -> Self {
        Self {
            check: Box::new(move || flag.load(Ordering::Relaxed)),
        }
    }

    /// A check from an arbitrary predicate.
    #[must_use]
    pub fn from_fn(f: impl Fn() -> bool + Send + Sync + 'a) -> Self {
        Self { check: Box::new(f) }
    }

    /// Returns `true` if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        (self.check)()
    }

    /// Returns `Err(GdsError::Cancelled)` if cancellation has been requested, else `Ok(())`.
    ///
    /// # Errors
    /// [`GdsError::Cancelled`] when the underlying predicate is `true`.
    pub fn check(&self) -> Result<(), GdsError> {
        if self.is_cancelled() {
            Err(GdsError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl Default for Cancel<'_> {
    fn default() -> Self {
        Self::never()
    }
}
