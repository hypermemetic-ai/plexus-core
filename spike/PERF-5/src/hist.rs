//! Latency in HdrHistogram: 1 ns to 60 s, three significant figures.

use std::time::Duration;

use hdrhistogram::Histogram;
use serde::Serialize;

pub struct Lat(Histogram<u64>);

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub n: u64,
    pub p50_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
}

impl Default for Lat {
    fn default() -> Self {
        Self::new()
    }
}

impl Lat {
    pub fn new() -> Self {
        Lat(Histogram::new_with_bounds(1, 60_000_000_000, 3).unwrap())
    }
    pub fn record(&mut self, d: Duration) {
        self.0.saturating_record(d.as_nanos().max(1) as u64);
    }
    pub fn record_us(&mut self, us: f64) {
        self.0.saturating_record((us * 1000.0).max(1.0) as u64);
    }
    pub fn summary(&self) -> Summary {
        let us = |ns: u64| ns as f64 / 1000.0;
        Summary {
            n: self.0.len(),
            p50_us: us(self.0.value_at_quantile(0.5)),
            p99_us: us(self.0.value_at_quantile(0.99)),
            p999_us: us(self.0.value_at_quantile(0.999)),
            max_us: us(self.0.max()),
            mean_us: self.0.mean() / 1000.0,
        }
    }
}
