//! PLEXUS-45: the runtime seam — the few runtime calls this crate makes
//! outside a test, in one place, so the crate runs on
//! `wasm32-unknown-unknown` as well as natively.
//!
//! **Native: exactly what was called before.** Every item is a re-export of
//! the tokio or std item each call site named (`tokio::spawn`,
//! `tokio::task::spawn_blocking`, `tokio::time::{sleep, timeout}`,
//! `std::time::Instant`), or, for [`now_unix`], the same `SystemTime`
//! arithmetic inlined — no wrapper, no new behaviour.
//!
//! **wasm32:** a browser (or node) has one thread and no tokio runtime, and
//! there `std::time::Instant::now`, `SystemTime::now`, `tokio::spawn` and
//! tokio's timers compile but panic at the first call. So:
//! - [`spawn`] is `wasm_bindgen_futures::spawn_local` (the event loop runs
//!   the task; there is no handle — no caller here keeps one);
//! - [`spawn_blocking`] runs the closure inline and answers at once: there
//!   is no other thread to move it to, and deferring it with `spawn_local`
//!   would only run the same work later on the same thread;
//! - [`sleep`] is a `setTimeout` (`futures-timer` over `gloo-timers`, so
//!   the future is `Send`), [`timeout`] races it;
//! - [`Instant`] and [`now_unix`] read the JS clock (`web-time`).

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    pub(crate) use std::time::Instant;
    pub(crate) use tokio::spawn;
    pub(crate) use tokio::task::spawn_blocking;
    pub(crate) use tokio::time::{sleep, timeout};

    /// Seconds since the Unix epoch, 0 before it.
    #[inline]
    pub(crate) fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::future::Future;
    use std::time::Duration;

    pub(crate) use web_time::Instant;

    /// Runs `future` on the JS event loop. No handle: nothing here keeps one.
    pub(crate) fn spawn<F>(future: F)
    where
        F: Future + 'static,
    {
        wasm_bindgen_futures::spawn_local(async move {
            let _ = future.await;
        });
    }

    /// Runs `f` here and now (one thread: nowhere else to run it); the
    /// answer is ready at the first poll. Never an error.
    pub(crate) fn spawn_blocking<F, R>(f: F) -> std::future::Ready<Result<R, std::convert::Infallible>>
    where
        F: FnOnce() -> R,
    {
        std::future::ready(Ok(f()))
    }

    /// A `setTimeout` of `duration` — `futures-timer`'s, which (unlike a
    /// bare `gloo-timers` future) is `Send`, as the streams it sits in must be.
    pub(crate) fn sleep(duration: Duration) -> futures_timer::Delay {
        futures_timer::Delay::new(duration)
    }

    /// `future`'s output, or [`Elapsed`] once `duration` has passed first.
    pub(crate) async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
        use futures::future::{select, Either};
        let future = std::pin::pin!(future);
        match select(future, sleep(duration)).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(((), _)) => Err(Elapsed(())),
        }
    }

    /// A [`timeout`] that ran out, as tokio's `Elapsed` is natively.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Elapsed(());

    impl std::fmt::Display for Elapsed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("deadline has elapsed")
        }
    }

    impl std::error::Error for Elapsed {}

    /// Seconds since the Unix epoch, from the JS clock; 0 before it.
    pub(crate) fn now_unix() -> i64 {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

pub(crate) use imp::*;
