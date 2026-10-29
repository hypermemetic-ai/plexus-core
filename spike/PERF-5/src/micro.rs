//! A microbench loop: warm up, then three runs, the median ns per op —
//! the house's rule (three runs, median) at nanosecond scale. Allocations
//! per op from the counting allocator (this thread's), measured apart.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Micro {
    pub name: String,
    pub ns_per_op: f64,
    pub runs_ns: Vec<f64>,
    pub allocs_per_op: f64,
    pub alloc_bytes_per_op: f64,
}

pub fn bench<F: FnMut()>(name: &str, mut f: F) -> Micro {
    // calibrate: ops in ~50 ms
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        if t.elapsed() > Duration::from_millis(50) {
            break;
        }
        n *= 2;
    }
    let per_run = n * 6; // ~300 ms a run
    for _ in 0..n {
        f();
    }
    let mut runs = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        for _ in 0..per_run {
            f();
        }
        runs.push(t.elapsed().as_nanos() as f64 / per_run as f64);
    }
    let mut sorted = runs.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    crate::alloc::enable(true);
    let a0 = crate::alloc::thread_snapshot();
    let k = 1000.min(per_run);
    for _ in 0..k {
        f();
    }
    let d = crate::alloc::thread_snapshot() - a0;
    crate::alloc::enable(false);
    Micro { name: name.into(), ns_per_op: sorted[1], runs_ns: runs, allocs_per_op: d.allocs as f64 / k as f64, alloc_bytes_per_op: d.bytes as f64 / k as f64 }
}

pub fn emit(m: &Micro, extra: serde_json::Value) {
    let mut v = serde_json::to_value(m).unwrap();
    if let serde_json::Value::Object(e) = extra {
        for (k, x) in e {
            v[k] = x;
        }
    }
    v["loadavg"] = std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().take(3).collect::<Vec<_>>().join(" ").into();
    println!("{v}");
}
