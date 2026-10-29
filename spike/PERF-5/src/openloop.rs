//! The open-loop schedule: request i is *meant* to go at start + i / rate,
//! and its latency is measured from then — never from when the client got
//! round to sending it — so a server stall is charged to every request that
//! should have gone during it (no coordinated omission).

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    start: Instant,
    every_ns: f64,
}

impl Schedule {
    pub fn new(start: Instant, rate_per_s: f64) -> Self {
        Schedule { start, every_ns: 1e9 / rate_per_s }
    }
    pub fn intended(&self, i: u64) -> Instant {
        self.start + Duration::from_nanos((i as f64 * self.every_ns).round() as u64)
    }
    /// Wait until request i is due (a sleep, then a short spin for the last 50 µs).
    pub async fn until(&self, i: u64) -> Instant {
        let at = self.intended(i);
        let now = Instant::now();
        if at > now + Duration::from_micros(200) {
            tokio::time::sleep_until((at - Duration::from_micros(50)).into()).await;
        }
        while Instant::now() < at {
            std::hint::spin_loop();
        }
        at
    }
}
