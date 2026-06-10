//! Graceful-shutdown coordination (`04-technical-design.md` §9.4).
//!
//! A [`ShutdownCoordinator`] is a cheap, cloneable broadcast of a single "shut down now" edge,
//! built on [`tokio::sync::watch`] (latest-wins, many awaiters — the right primitive for a one-shot
//! fan-out signal). Every accept loop and connection task holds a clone and selects on
//! [`ShutdownCoordinator::wait`]; the server fires it once (on a signal or an admin request) and all
//! awaiters wake.
//!
//! [`wait_for_signal`] resolves on SIGTERM or SIGINT (Ctrl-C), the two signals a service must handle
//! for an orderly stop (Source: Tokio graceful-shutdown pattern).

use tokio::sync::watch;

/// A cloneable broadcast of the shutdown edge.
///
/// Cloning shares the same underlying channel, so a [`trigger`](Self::trigger) on any clone wakes
/// every [`wait`](Self::wait) on every clone.
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    /// `false` until shutdown is requested, then `true` (and stays `true`).
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownCoordinator {
    /// A fresh coordinator in the not-yet-shutting-down state.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx, rx }
    }

    /// Requests shutdown, waking every current and future [`wait`](Self::wait). Idempotent.
    pub fn trigger(&self) {
        // Ignore the error: a closed channel means every receiver was already dropped, so there is
        // nothing left to wake — which is fine on a late trigger.
        let _ = self.tx.send(true);
    }

    /// Whether shutdown has already been requested (non-blocking probe).
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves when shutdown is requested (immediately if it already has been).
    ///
    /// Cancellation-safe: it awaits a `watch` change, which can be dropped and re-created freely. A
    /// caller typically `select!`s this against its own work.
    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        // If already triggered, return at once.
        if *rx.borrow() {
            return;
        }
        // Otherwise await the edge to `true`. `changed()` errors only if the sender dropped; treat a
        // dropped sender as "shut down" (the server is gone) so the awaiter does not hang.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

/// Resolves on the first SIGTERM or SIGINT (Ctrl-C) the process receives (`04 §9.4`).
///
/// On non-Unix platforms only Ctrl-C is awaited (SIGTERM is Unix-specific); Graphus targets Linux
/// and macOS (`CLAUDE.md`), both Unix, so SIGTERM is always available in practice.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // If a signal handler cannot be installed, fall back to Ctrl-C alone rather than aborting.
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGTERM handler; using Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_returns_after_trigger() {
        let sc = ShutdownCoordinator::new();
        assert!(!sc.is_triggered());
        let waiter = {
            let sc = sc.clone();
            tokio::spawn(async move { sc.wait().await })
        };
        // Give the waiter a moment to start awaiting, then trigger.
        tokio::task::yield_now().await;
        sc.trigger();
        assert!(sc.is_triggered());
        // The waiter must complete promptly.
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("waiter should wake")
            .expect("task ok");
    }

    #[tokio::test]
    async fn wait_returns_immediately_if_already_triggered() {
        let sc = ShutdownCoordinator::new();
        sc.trigger();
        // Already triggered: wait resolves at once.
        tokio::time::timeout(std::time::Duration::from_millis(100), sc.wait())
            .await
            .expect("already-triggered wait resolves immediately");
    }

    #[tokio::test]
    async fn clones_share_the_signal() {
        let a = ShutdownCoordinator::new();
        let b = a.clone();
        let waiter = tokio::spawn(async move { b.wait().await });
        tokio::task::yield_now().await;
        a.trigger();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("clone wakes")
            .expect("task ok");
    }
}
