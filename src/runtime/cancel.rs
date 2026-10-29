//! The per-turn cancellation token (PLX-80 / M1·C).
//!
//! # The contract, stated once and precisely
//!
//! A [`CancellationToken`] is a **signal**, not an abort. Read
//! [`crate::runtime`] for the full boundary; the short form is:
//!
//! - the framework guarantees the signal is *delivered* (the token flips and
//!   every [`CancellationToken::cancelled`] waiter wakes), that the turn
//!   *resolves* with [`StopKind::Cancelled`](crate::ir::StopKind::Cancelled),
//!   and that in-flight callbacks *resolve* rather than hang;
//! - the framework guarantees **nothing** about the handler's work. A spawned
//!   subprocess, an in-flight model call, or a half-written row is the
//!   implementor's responsibility.
//!
//! # Why this is hand-rolled
//!
//! `tokio_util::sync::CancellationToken` is the obvious off-the-shelf choice,
//! but it would add `tokio-util` to plexus-core's dependency set for roughly
//! forty lines of `AtomicBool` + [`tokio::sync::Notify`]. The primitive is
//! small, the semantics are exactly what the turn contract needs, and no
//! dependency is worth owning for it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

#[derive(Debug)]
struct Inner {
    cancelled: AtomicBool,
    notify: Notify,
}

/// A cheaply-clonable cancellation signal shared by a turn's runtime, its
/// handler, and its in-flight callbacks.
///
/// Every clone observes the same state; cancelling any clone cancels all of
/// them. Cancellation is one-way and idempotent.
///
/// ```
/// # use plexus_core::runtime::CancellationToken;
/// # tokio_test::block_on(async {
/// let token = CancellationToken::new();
/// let observer = token.clone();
/// assert!(!observer.is_cancelled());
/// token.cancel();
/// observer.cancelled().await; // returns immediately
/// assert!(observer.is_cancelled());
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct CancellationToken {
    inner: Arc<Inner>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    /// A fresh, uncancelled token.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Deliver the cancel signal. Idempotent; safe from any thread.
    ///
    /// This flips the flag and wakes every current [`Self::cancelled`] waiter.
    /// It does **not** stop anything by itself — see the module docs.
    pub fn cancel(&self) {
        // `swap` so repeated cancels do not repeatedly wake waiters, and so
        // the "was it already cancelled" answer is race-free.
        if !self.inner.cancelled.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    /// Whether the signal has been delivered. The cheap polling form, for a
    /// handler that checks between units of work.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Resolve once the signal has been delivered.
    ///
    /// Returns immediately if the token is already cancelled. Safe to call
    /// from many tasks; all of them wake.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);
        // Register the waiter *before* re-checking the flag, so a `cancel()`
        // that lands between the two observations still wakes us.
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }

    /// Run `fut` unless (or until) the token is cancelled.
    ///
    /// An ergonomic wrapper for the common cooperative pattern. `None` means
    /// the signal arrived first; it does **not** mean `fut`'s work stopped —
    /// `fut` is dropped, which stops a pure-async computation and stops
    /// nothing else.
    pub async fn run_until<F: std::future::Future>(&self, fut: F) -> Option<F::Output> {
        tokio::select! {
            biased;
            _ = self.cancelled() => None,
            out = fut => Some(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancel_is_observable_by_every_clone() {
        let a = CancellationToken::new();
        let b = a.clone();
        let c = a.clone();
        assert!(!b.is_cancelled());
        a.cancel();
        assert!(b.is_cancelled());
        c.cancelled().await;
    }

    #[tokio::test]
    async fn cancel_is_idempotent() {
        let t = CancellationToken::new();
        t.cancel();
        t.cancel();
        assert!(t.is_cancelled());
        t.cancelled().await;
    }

    #[tokio::test]
    async fn waiters_registered_before_cancel_are_woken() {
        let t = CancellationToken::new();
        let observer = t.clone();
        let waiter = tokio::spawn(async move {
            observer.cancelled().await;
            true
        });
        tokio::task::yield_now().await;
        t.cancel();
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn run_until_yields_none_on_cancel() {
        let t = CancellationToken::new();
        t.cancel();
        let out = t
            .run_until(async {
                futures::future::pending::<()>().await;
            })
            .await;
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn run_until_yields_the_value_when_not_cancelled() {
        let t = CancellationToken::new();
        assert_eq!(t.run_until(async { 7 }).await, Some(7));
    }
}
