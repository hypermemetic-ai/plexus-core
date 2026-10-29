//! POLYGLOT-5 — `hop_perf`: what the child seam costs, as rows of JSON.
//!
//!   cargo test --release -p plexus-core --test remote_child_perf -- --ignored --nocapture hop_perf
//!
//! Any child speaking the reference surface (`echo(text, times)`,
//! `count(to, delay_ms)`) is measured in the stub's place — the server kits
//! run it against theirs:
//!
//!   PLEXUS_PERF_CHILD="plexus-child serve examples.echo.echo:Echo --stdio"   # a stdio child
//!   PLEXUS_PERF_CHILD_URL=ws://127.0.0.1:4480 PLEXUS_PERF_CHILD_KEY=~/.plexus/keys/x.key   # a ws child
//!
//! Each row prints `ROW {json}` with `target` and `met`; the test fails when
//! a row is past twice its target (a debug build measures nothing: it
//! prints and asserts nothing). Rows that need the stub's extras (`burst`,
//! `--log`'s stop times) are skipped for another child.

mod child_support;

use child_support::*;
use futures::StreamExt;
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::{ChildOptions, ChildSpec, HubTransport, RemoteChild};
use plexus_core::DynamicHub;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Rows {
    failed: Vec<String>,
}

impl Rows {
    /// A row: `value` against `target` (`le`: at most; else at least).
    fn row(&mut self, name: &str, value: f64, target: f64, le: bool, extra: Value) {
        let met = if le { value <= target } else { value >= target };
        let ci = if le { value <= 2.0 * target } else { value >= target / 2.0 };
        println!("ROW {}", json!({ "row": name, "value": value, "target": format!("{} {target}", if le { "<=" } else { ">=" }), "met": met, "detail": extra }));
        if !ci {
            self.failed.push(format!("{name}: {value} past twice its target {target}"));
        }
    }
}

fn custom() -> bool {
    std::env::var_os("PLEXUS_PERF_CHILD").is_some() || std::env::var_os("PLEXUS_PERF_CHILD_URL").is_some()
}

/// The child under measure on stdio, mounted as `echo`.
fn stdio_child(dir: &std::path::Path) -> ChildSpec {
    match std::env::var("PLEXUS_PERF_CHILD") {
        Ok(cmd) => format!("echo=stdio:{cmd}").parse().unwrap(),
        Err(_) => stdio_spec("echo", &dir.join("perf.log"), ""),
    }
}

async fn time_calls(t: &HubTransport, ns: &'static str, n: usize) -> Vec<f64> {
    for _ in 0..50 {
        collect(t, ns, "echo", json!({ "text": "hi", "times": 1 })).await;
    }
    let mut ts = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let items = collect(t, ns, "echo", json!({ "text": "hi", "times": 1 })).await;
        ts.push(t0.elapsed().as_secs_f64() * 1e3);
        assert_eq!(kinds(&items), ["data", "done"], "{items:?}");
    }
    ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    ts
}

async fn ws_rate(ws: &plexus_client::WsTransport, ns: &'static str, p: Value) -> f64 {
    let t0 = Instant::now();
    let mut s = ws.call(MethodRef::new(ns, "count"), p);
    let mut n = 0usize;
    while let Some(i) = s.next().await {
        if let Ok(StreamItem::Data { .. }) = i {
            n += 1;
        }
    }
    assert_eq!(n, 10000);
    n as f64 / t0.elapsed().as_secs_f64()
}

/// The stub's own rate: `count` read straight off its stdout, no service —
/// what the hop's in-memory stream is measured against (the hop keeps a
/// share of what the child makes).
async fn stub_alone(to: u64) -> f64 {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut c = tokio::process::Command::new("python3")
        .args(["-I", &stub().display().to_string(), "--stdio", "--log", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    let mut lines = BufReader::new(c.stdout.take().unwrap()).lines();
    let hop = json!({ "principal": "service:bench", "for": [], "limit": { "grant": "echo.count", "held_on": ["*"] }, "call": "alone" });
    let mut best = 0f64;
    for i in 0..3 {
        let frame = json!({ "jsonrpc": "2.0", "id": i, "method": "echo.call", "params": { "method": "echo.count", "params": { "to": to }, "hop": hop } });
        let t0 = Instant::now();
        stdin.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        let mut n = 0u64;
        while let Some(l) = lines.next_line().await.unwrap() {
            let v: Value = serde_json::from_str(&l).unwrap();
            match v.pointer("/params/result/type").and_then(Value::as_str) {
                Some("data") => n += 1,
                Some("done") => break,
                _ => {}
            }
        }
        best = best.max(n as f64 / t0.elapsed().as_secs_f64());
    }
    drop(stdin);
    let _ = c.wait().await;
    best
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf: run in release with --ignored"]
async fn hop_perf() {
    if cfg!(debug_assertions) {
        eprintln!("hop_perf measures a release build: cargo test --release … -- --ignored hop_perf");
        return;
    }
    let mut rows = Rows { failed: vec![] };
    let dir = tempfile::tempdir().unwrap();
    let key = test_key(dir.path(), "service", [9u8; 32]);

    // 1 · the hop's cost, one-item calls, stdio, in memory.
    let r0 = rss_kib();
    let child = RemoteChild::connect(stdio_child(dir.path()), ChildOptions::default()).await.unwrap();
    let first_child_kib = rss_kib().saturating_sub(r0);
    let service = Arc::new(DynamicHub::new("service").register(RsechoActivation).register(child.clone()));
    let t = HubTransport::anonymous(service.clone());
    let inproc = time_calls(&t, "rsecho", 1000).await;
    let hop = time_calls(&t, "echo", 1000).await;
    let detail = json!({ "p99_ms": pct(&hop, 0.99), "max_ms": hop[hop.len() - 1], "inproc_p50_ms": pct(&inproc, 0.5), "inproc_p99_ms": pct(&inproc, 0.99) });
    rows.row("hop p50, stdio (ms)", pct(&hop, 0.5), 0.5, true, detail.clone());
    rows.row("hop p99, stdio (ms)", pct(&hop, 0.99), 2.0, true, detail);

    // 2 · the same over a WebSocket child, dialed with the service's key.
    let ws_stub_proc = if custom() { None } else { Some(ws_stub(dir.path(), &key.principal, &[])) };
    let ws_url = std::env::var("PLEXUS_PERF_CHILD_URL").ok().or_else(|| ws_stub_proc.as_ref().map(|s| format!("ws://127.0.0.1:{}", s.port)));
    if let Some(url) = &ws_url {
        let key_path = std::env::var_os("PLEXUS_PERF_CHILD_KEY").map(Into::into).unwrap_or(key.path.clone());
        let far = RemoteChild::connect(format!("echo=ws://{}", url.trim_start_matches("ws://")).parse().unwrap(), ChildOptions { key: Some(key_path), ..ChildOptions::default() }).await.unwrap();
        let s2 = Arc::new(DynamicHub::new("service").register(far.clone()));
        let t2 = HubTransport::anonymous(s2);
        let ws_hop = time_calls(&t2, "echo", 1000).await;
        let detail = json!({ "p99_ms": pct(&ws_hop, 0.99), "max_ms": ws_hop[ws_hop.len() - 1] });
        rows.row("hop p50, ws loopback (ms)", pct(&ws_hop, 0.5), 0.5, true, detail.clone());
        rows.row("hop p99, ws loopback (ms)", pct(&ws_hop, 0.99), 2.0, true, detail);
    }

    // 3 · a 10,000-item stream as a caller sees it: over the service's
    // WebSocket, the child against the in-process Rust echo (POLYGLOT-4:
    // in memory compares a process with a path that serialises nothing).
    let (addr, handle) = serve(service.clone()).await;
    let ws = plexus_client::WsTransport::connect(&format!("ws://{addr}"), "service").await.unwrap();
    let (mut a, mut b) = (0f64, 0f64);
    for _ in 0..5 {
        a = a.max(ws_rate(&ws, "rsecho", json!({ "to": 10000 })).await);
        b = b.max(ws_rate(&ws, "echo", json!({ "to": 10000 })).await);
    }
    let mut mem = (0f64, 0f64);
    for _ in 0..3 {
        let t0 = Instant::now();
        let x = collect(&t, "rsecho", "count", json!({ "to": 10000 })).await;
        mem.0 = mem.0.max((x.len() - 1) as f64 / t0.elapsed().as_secs_f64());
        let t0 = Instant::now();
        let y = collect(&t, "echo", "count", json!({ "to": 10000 })).await;
        mem.1 = mem.1.max((y.len() - 1) as f64 / t0.elapsed().as_secs_f64());
    }
    let mut ceiling = 0f64;
    let alone = if custom() { 0.0 } else { stub_alone(10000).await };
    if !custom() {
        for _ in 0..3 {
            let t0 = Instant::now();
            let z = collect(&t, "echo", "count", json!({ "to": 10000, "burst": true })).await;
            assert_eq!(z.len(), 10001);
            ceiling = ceiling.max(10000.0 / t0.elapsed().as_secs_f64());
        }
    }
    rows.row("10,000-item stream over the WebSocket, child / in process", b / a, 0.9, false,
        json!({ "ws_inproc_items_s": a, "ws_child_items_s": b, "mem_inproc_items_s": mem.0, "mem_child_items_s": mem.1, "hop_ceiling_items_s": ceiling, "stub_alone_on_its_pipe_items_s": alone, "mem_child_vs_stub_alone": mem.1 / alone.max(1.0) }));
    handle.stop().unwrap();

    // 4 · cancel: the caller drops at item 100; the child's own clock of its stop.
    if !custom() {
        let log = dir.path().join("perf.log");
        let mut lat = vec![];
        for _ in 0..100 {
            let mut s = t.call(MethodRef::new("echo", "count"), json!({ "to": 100000, "delay_ms": 1 }));
            let mut got = 0;
            while got < 100 {
                if let Some(Ok(StreamItem::Data { .. })) = s.next().await {
                    got += 1;
                }
            }
            let dropped = unix_ns();
            drop(s);
            let stopped = child_event(&log, "stopped", dropped, Duration::from_secs(2)).await.expect("stopped");
            lat.push((stopped - dropped) as f64 / 1e6);
        }
        lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        rows.row("cancel → the child stopped, p99 (ms)", pct(&lat, 0.99), 100.0, true, json!({ "p50_ms": pct(&lat, 0.5), "max_ms": lat[lat.len() - 1], "runs": lat.len() }));
    }

    // 5 · the schema's merge at mount.
    let m = child.mount_timings();
    rows.row("schema merge at mount (ms)", m.merge_ms, 20.0, true, json!({ "spawn_ms": m.spawn_ms, "schema_ms": m.schema_ms }));

    // 6 · memory per idle child, after the first (the first brings the
    // process machinery: recorded beside it).
    let r1 = rss_kib();
    let mut kids = vec![];
    for i in 0..8 {
        let spec: ChildSpec = match std::env::var("PLEXUS_PERF_CHILD") {
            Ok(cmd) => format!("echo{i}=stdio:{cmd}").parse().unwrap(),
            Err(_) => stdio_spec(&format!("echo{i}"), &dir.path().join(format!("m{i}.log")), ""),
        };
        kids.push(RemoteChild::connect(spec, ChildOptions::default()).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let per_child = rss_kib().saturating_sub(r1) as f64 / 8.0;
    let s8 = Arc::new(kids.iter().fold(DynamicHub::new("service"), |h, k| h.register(k.clone())));
    let t8 = HubTransport::anonymous(s8);
    let r8 = rss_kib();
    let mut open = vec![];
    for _ in 0..100 {
        let mut s = t8.call(MethodRef::new("echo0", "count"), json!({ "to": 1000000, "delay_ms": 100 }));
        let _ = s.next().await;
        open.push(s);
    }
    let per_call = rss_kib().saturating_sub(r8) as f64 / 100.0;
    rows.row("service RSS per idle child, after the first (KiB)", per_child, 200.0, true, json!({ "first_child_kib": first_child_kib, "per_open_call_kib": per_call }));
    drop(open);

    // 7 · head-of-line: one caller stops reading a burst; another call on
    // the same child waits behind it (lossless), measured.
    if !custom() {
        let quiet = time_calls(&t, "echo", 200).await;
        let mut stalled = t.call(MethodRef::new("echo", "count"), json!({ "to": 50000, "burst": true }));
        let _ = stalled.next().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = Instant::now();
        let blocked = tokio::time::timeout(Duration::from_millis(300), collect(&t, "echo", "echo", json!({ "text": "hi", "times": 1 }))).await.is_err();
        let waited = t0.elapsed().as_secs_f64() * 1e3;
        drop(stalled);
        rows.row("head-of-line: a call behind a stalled caller (blocked = 1)", if blocked { 1.0 } else { 0.0 }, 1.0, true,
            json!({ "quiet_p99_ms": pct(&quiet, 0.99), "waited_ms": waited, "note": "the per-call buffer is bounded (1,024): past it the child's reader waits, so its other calls wait — lossless, recorded" }));
    }

    assert!(rows.failed.is_empty(), "{:?}", rows.failed);
}
