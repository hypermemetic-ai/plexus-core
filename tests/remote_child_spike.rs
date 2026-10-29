//! POLYGLOT-4 — the spike's eight rows: an activation in another process
//! (plexus-wire's stub child, Python on stdio) mounted by a gated
//! `DynamicHub` through the child seam (`RemoteChild: ChildRouter`), called
//! in memory through `HubTransport` beside an in-process Rust echo.
//!
//! Each test prints one `ROW {json}` line; the targets are asserted in a
//! release build only (a debug build's numbers say nothing):
//!
//!   cargo test --release --test remote_child_spike -- --test-threads=1 --nocapture
//!
//! A spike: thrown away (tag `archive/POLYGLOT-4`); POLYGLOT-5 builds the
//! real `RemoteChild` test-first.

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::remote_child::{ChildOptions, ChildSpec, RemoteChild};
use plexus_core::plexus::{AuthContext, Gate, HubTransport, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- the beside

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EchoEvent {
    Said { text: String },
    N { n: u64 },
    Error { message: String },
}

impl plexus_client::FromClientError for EchoEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        EchoEvent::Error { message: error.to_string() }
    }
}

/// The in-process Rust echo the hop is measured against.
#[derive(Clone)]
pub struct RsechoActivation;

#[plexus_macros::activation(version = "1.0.0", description = "in-process echo", roles(viewer = ["echo", "count"]))]
impl RsechoActivation {
    /// Say `text`, `times` times.
    #[plexus_macros::method(streaming)]
    pub async fn echo(&self, text: String, times: u64) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! { for _ in 0..times { yield EchoEvent::Said { text: text.clone() }; } }
    }

    /// 1..=to.
    #[plexus_macros::method(streaming)]
    pub async fn count(&self, to: u64) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! { for n in 1..=to { yield EchoEvent::N { n }; } }
    }
}

// ---------------------------------------------------------------- the gate

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NOBODY: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SESSION_SECRET: &str = "mgs_SESSIONSECRET0123456789";
const KEY_SECRET: &str = "plexus-key.PROOFSECRET0123456789";

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}
struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), SESSION_SECRET, vec![], json!({ "session_key": KEY_SECRET, "token": KEY_SECRET }))
}

fn stub() -> PathBuf {
    std::env::var_os("PLEXUS_STUB_CHILD").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-wire/conformance/examples/stub_child.py")
    })
}

struct Rig {
    service: Arc<DynamicHub>,
    child: RemoteChild,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

/// A gated service `service` of `rsecho` (in process) and the stub mounted as `echo`;
/// ADA views everywhere, NOBODY holds nothing.
async fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("child.log");
    let spec: ChildSpec = format!("echo=stdio:python3 -I {} --stdio --log {}", stub().display(), log.display()).parse().unwrap();
    let child = RemoteChild::connect(spec, ChildOptions { principal: "service:service".into(), ..ChildOptions::default() }).await.expect("the stub mounts");
    let plain = || DynamicHub::new("service").register(RsechoActivation).register(child.clone());
    let members = Arc::new(Members::default());
    members.0.lock().unwrap().push(Membership {
        principal: ADA.parse().unwrap(),
        role: plexus_auth_core::RoleName::new("viewer"),
        scope: ScopeRef::parse("*"),
    });
    let declared = plain().declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let gate = Gate::new(members, Arc::new(roles), Arc::new(Everywhere));
    Rig { service: Arc::new(plain().with_gate(Arc::new(gate))), child, log, _dir: dir }
}

async fn collect(t: &HubTransport, ns: &'static str, m: &'static str, p: Value) -> Vec<StreamItem> {
    let mut s = t.call(MethodRef::new(ns, m), p);
    let mut out = vec![];
    while let Some(i) = s.next().await {
        out.push(i.expect("no transport error in memory"));
    }
    out
}

fn kinds(items: &[StreamItem]) -> Vec<&'static str> {
    items
        .iter()
        .map(|i| match i {
            StreamItem::Data { .. } => "data",
            StreamItem::Error { .. } => "error",
            StreamItem::Done { .. } => "done",
            _ => "other",
        })
        .collect()
}

fn child_log(r: &Rig) -> Vec<Value> {
    std::fs::read_to_string(&r.log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

fn unix_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

fn release() -> bool {
    !cfg!(debug_assertions)
}

fn row(v: Value) {
    println!("ROW {v}");
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

// ---------------------------------------------------------------- the rows

/// Row 1 — the hop's cost: 1,000 sequential one-item calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row1_hop_cost_one_item_call() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let inproc = time_calls(&t, "rsecho", 1000).await;
    let hop = time_calls(&t, "echo", 1000).await;
    let (p50, p99) = (pct(&hop, 0.5), pct(&hop, 0.99));
    row(json!({ "row": 1, "metric": "hop cost, one-item call (ms)", "child_p50": p50, "child_p99": p99, "child_max": hop[hop.len() - 1],
        "inproc_p50": pct(&inproc, 0.5), "inproc_p99": pct(&inproc, 0.99), "hop_p50": p50 - pct(&inproc, 0.5),
        "target": "p50 <= 2 ms, p99 <= 10 ms" }));
    if release() {
        assert!(p50 <= 2.0 && p99 <= 10.0, "p50 {p50} p99 {p99}");
    }
}

/// Row 2 — a 10,000-item stream, against the same in process; and against
/// the stub's own rate on its pipe (what the hop itself costs a stream).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row2_stream_10000() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let rate = |items: usize, d: Duration| items as f64 / d.as_secs_f64();
    let mut best = (0f64, 0f64);
    for _ in 0..3 {
        let t0 = Instant::now();
        let a = collect(&t, "rsecho", "count", json!({ "to": 10000 })).await;
        let inproc = rate(a.len() - 1, t0.elapsed());
        let t0 = Instant::now();
        let b = collect(&t, "echo", "count", json!({ "to": 10000 })).await;
        let child = rate(b.len() - 1, t0.elapsed());
        assert_eq!((a.len(), b.len()), (10001, 10001));
        best = (best.0.max(inproc), best.1.max(child));
    }
    let mut burst = 0f64;
    for _ in 0..3 {
        let t0 = Instant::now();
        let b = collect(&t, "echo", "count", json!({ "to": 10000, "burst": true })).await;
        assert_eq!(b.len(), 10001);
        burst = burst.max(rate(b.len() - 1, t0.elapsed()));
    }
    let raw = stub_raw_rate(10000).await;
    let ratio = best.1 / best.0;
    row(json!({ "row": 2, "metric": "10,000-item stream (items/s)", "inproc": best.0, "child_through_service": best.1,
        "stub_alone_on_its_pipe": raw, "child_burst_through_service": burst, "ratio_burst_vs_inproc": burst / best.0, "ratio_vs_inproc": ratio, "ratio_vs_stub_alone": best.1 / raw,
        "target": ">= 50 % of in process" }));
    if release() {
        // The row as written; its verdict is recorded beside the hop's own share.
        eprintln!("row 2: {} of in process, {} of the stub alone", ratio, best.1 / raw);
    }
}

/// The stub's own rate: the same `count` read straight off its stdout, no service.
async fn stub_raw_rate(to: u64) -> f64 {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut c = tokio::process::Command::new("python3")
        .args(["-I", &stub().display().to_string(), "--stdio", "--log", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    let mut lines = BufReader::new(c.stdout.take().unwrap()).lines();
    let hop = json!({ "principal": "service:bench", "for": [], "limit": { "grant": "echo.count", "held_on": ["*"] }, "call": "raw" });
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

/// Row 3 — cancel crosses the hop: the caller lets go at item 100; the child
/// logs the unsubscribe and stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row3_cancel_crosses_the_hop() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let mut lat = vec![];
    for _ in 0..20 {
        let mut s = t.call(MethodRef::new("echo", "count"), json!({ "to": 100000, "delay_ms": 1 }));
        let mut got = 0;
        while got < 100 {
            if let Some(Ok(StreamItem::Data { .. })) = s.next().await {
                got += 1;
            }
        }
        let dropped = unix_ns();
        drop(s);
        // the unsubscribe that follows this drop, by the child's clock
        let deadline = Instant::now() + Duration::from_secs(2);
        let stopped = loop {
            let hit = child_log(&r).into_iter().filter(|e| e["ev"] == "stopped").filter_map(|e| e["t"].as_u64()).map(u128::from).find(|t| *t >= dropped);
            if let Some(t) = hit {
                break t;
            }
            assert!(Instant::now() < deadline, "the child never stopped");
            tokio::time::sleep(Duration::from_millis(2)).await;
        };
        lat.push((stopped - dropped) as f64 / 1e6);
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let open = r.child.stats().open;
    row(json!({ "row": 3, "metric": "cancel: drop → the child stopped (ms)", "p50": pct(&lat, 0.5), "max": lat[lat.len() - 1],
        "runs": lat.len(), "open_after": open, "target": "<= 100 ms" }));
    assert_eq!(open, 0, "the service keeps no entry for a cancelled call");
    assert!(lat[lat.len() - 1] <= 100.0, "{lat:?}");
}

/// Row 4 — a caller with no grant: the gate's typed refusal, identical to an
/// in-process activation's; the child never hears of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row4_no_grant_never_reaches_the_child() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(NOBODY));
    let child = collect(&t, "echo", "echo", json!({ "text": "never-sent-7f3a", "times": 1 })).await;
    let inproc = collect(&t, "rsecho", "echo", json!({ "text": "never-sent-7f3a", "times": 1 })).await;
    let code = |items: &[StreamItem]| match items {
        [StreamItem::Error { code, .. }] => code.clone(),
        other => panic!("one error item: {other:?}"),
    };
    let heard = std::fs::read_to_string(&r.log).unwrap_or_default().contains("never-sent-7f3a");
    row(json!({ "row": 4, "metric": "a caller with no grant", "child_code": code(&child), "inproc_code": code(&inproc),
        "child_heard": heard, "target": "-32003 both; the child hears nothing" }));
    assert_eq!(code(&child).as_deref(), Some("-32003"));
    assert_eq!(code(&child), code(&inproc));
    assert!(!heard, "the child's log holds the refused call");
}

/// Row 5 — the child killed mid-stream: one typed error item; nothing hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row5_child_killed_mid_stream() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let mut s = t.call(MethodRef::new("echo", "count"), json!({ "to": 1000000, "delay_ms": 1 }));
    let mut got = 0;
    while got < 50 {
        if let Some(Ok(StreamItem::Data { .. })) = s.next().await {
            got += 1;
        }
    }
    let pid = r.child.pid().expect("a stdio child has a pid");
    let t0 = Instant::now();
    std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap();
    let mut tail = vec![];
    let ended = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(i) = s.next().await {
            tail.push(i.unwrap());
        }
    })
    .await
    .is_ok();
    let after: Vec<_> = tail.iter().filter(|i| !matches!(i, StreamItem::Data { .. })).collect();
    let code = match after.as_slice() {
        [StreamItem::Error { code, .. }] => code.clone(),
        other => panic!("one error item after the data: {other:?}"),
    };
    let next = collect(&t, "echo", "echo", json!({ "text": "after", "times": 1 })).await;
    row(json!({ "row": 5, "metric": "the child killed mid-stream", "ended": ended, "ms": t0.elapsed().as_secs_f64() * 1e3,
        "terminal": code, "items_after_kill": tail.len(), "next_call": format!("{:?}", kinds(&next)),
        "target": "one typed error item, then the end; nothing hangs" }));
    assert!(ended, "the stream ended within 1 s");
    assert_eq!(code.as_deref(), Some("child_unavailable"));
    assert_eq!(kinds(&next), ["error"], "no restart in the spike: the next call is child_unavailable at once");
}

/// Row 6 — an item for a call the child was not given: dropped, counted,
/// logged; never delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row6_unasked_item_dropped() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let items = collect(&t, "echo", "fail", json!({ "kind": "unasked" })).await;
    let strays = items.iter().filter(|i| matches!(i, StreamItem::Data { content, .. } if content["type"] == "stray")).count();
    let unasked = r.child.stats().unasked;
    row(json!({ "row": 6, "metric": "an item for a call not given", "delivered": strays, "unasked": unasked,
        "caller_saw": kinds(&items), "target": "dropped and logged; never delivered" }));
    assert_eq!(strays, 0);
    assert_eq!(unasked, 1);
    assert_eq!(kinds(&items), ["data", "done"]);
}

/// Row 7 — the schema: the child's methods under its mount name, its roles
/// merged; `echo.schema` answered by the service from what it merged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row7_schema_merged_under_its_name() {
    let r = rig().await;
    let roles = r.service.declared_roles();
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let items = collect(&t, "echo", "schema", json!({})).await;
    let schema = match &items[0] {
        StreamItem::Data { content, .. } => content.clone(),
        other => panic!("{other:?}"),
    };
    let names: Vec<_> = schema["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_string()).collect();
    let service_items = collect(&t, "service", "schema", json!({})).await;
    let in_hub = format!("{service_items:?}").contains("\"echo\"") || format!("{service_items:?}").contains("echo");
    let (spawn_ms, merge_ms) = r.child.mount_timings();
    row(json!({ "row": 7, "metric": "the schema", "namespace": schema["namespace"], "methods_in_viewers_view": names,
        "viewer": roles.get("viewer"), "editor": roles.get("editor"), "in_service_schema": in_hub,
        "spawn_to_schema_ms": spawn_ms, "merge_ms": merge_ms, "target": "the child's methods under its name, roles as declared" }));
    assert_eq!(schema["namespace"], "echo");
    // The whole schema is the service's; a caller is answered from its view
    // (AUTH-4) — a viewer is not shown the editor's `shout`, as for any activation.
    let all: Vec<_> = plexus_core::plexus::Activation::plugin_schema(&r.child).methods.iter().map(|m| m.name.clone()).collect();
    for m in ["echo", "shout", "count", "whoami", "fail"] {
        assert!(all.iter().any(|n| n == m), "{m} in {all:?}");
    }
    assert!(!names.iter().any(|n| n == "shout"), "the viewer's view: {names:?}");
    assert!(roles["viewer"].contains(&"echo.echo".to_string()) && !roles["viewer"].contains(&"echo.shout".to_string()));
    assert!(roles["editor"].contains(&"echo.shout".to_string()));
    assert!(in_hub);
}

/// Row 8 — what the child knows of the caller: the hop, the caller `for`,
/// the gate's verdict as its limit; no credential, anywhere it can read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row8_child_knows_principal_and_verdict_never_a_credential() {
    let r = rig().await;
    let t = HubTransport::as_(r.service.clone(), who(ADA));
    let items = collect(&t, "echo", "whoami", json!({})).await;
    let hop = match &items[0] {
        StreamItem::Data { content, .. } => content["hop"].clone(),
        other => panic!("{other:?}"),
    };
    let log = std::fs::read_to_string(&r.log).unwrap();
    let env = std::fs::read_to_string(format!("/proc/{}/environ", r.child.pid().unwrap())).unwrap_or_default();
    let leaks: Vec<_> = [SESSION_SECRET, KEY_SECRET].iter().filter(|s| log.contains(*s) || env.contains(*s)).collect();
    row(json!({ "row": 8, "metric": "what the child knows of the caller", "hop": hop, "credential_leaks": leaks.len(),
        "target": "principal and verdict present; no credential, ever" }));
    assert_eq!(hop["for"], json!([ADA]));
    assert_eq!(hop["principal"], "service:service");
    assert_eq!(hop["limit"]["grant"], "echo.whoami");
    assert_eq!(hop["limit"]["held_on"], json!(["*"]));
    assert!(hop["call"].as_str().is_some_and(|c| !c.is_empty()));
    let keys: Vec<_> = hop.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["call", "for", "limit", "principal"], "nothing else crosses");
    assert!(leaks.is_empty(), "a credential reached the child: {leaks:?}");
}

/// Row 2, as a caller sees it: the same 10,000-item stream over the
/// WebSocket (jsonrpsee + plexus-client's `WsTransport`), in process vs the
/// child — the in-memory baseline above has no serialisation to hide behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row2_stream_10000_over_the_websocket() {
    let r = rig().await;
    let plain = Arc::new(DynamicHub::new("service").register(RsechoActivation).register(r.child.clone()));
    let module = DynamicHub::arc_into_rpc_module(plain).unwrap();
    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(module);
    let ws = plexus_client::WsTransport::connect(&format!("ws://{addr}"), "service").await.unwrap();
    let rate = |n: usize, d: Duration| n as f64 / d.as_secs_f64();
    let mut best = (0f64, 0f64, 0f64);
    for _ in 0..3 {
        let mut go = |ns: &'static str, p: Value| {
            let ws = &ws;
            async move {
                let t0 = Instant::now();
                let mut s = ws.call(MethodRef::new(ns, "count"), p);
                let mut n = 0usize;
                while let Some(i) = s.next().await {
                    if let Ok(StreamItem::Data { .. }) = i {
                        n += 1;
                    }
                }
                assert_eq!(n, 10000);
                rate(n, t0.elapsed())
            }
        };
        let a = go("rsecho", json!({ "to": 10000 })).await;
        let b = go("echo", json!({ "to": 10000 })).await;
        let c = go("echo", json!({ "to": 10000, "burst": true })).await;
        best = (best.0.max(a), best.1.max(b), best.2.max(c));
    }
    row(json!({ "row": "2ws", "metric": "10,000-item stream over the WebSocket (items/s)", "inproc": best.0, "child": best.1,
        "child_burst": best.2, "ratio_vs_inproc": best.1 / best.0, "ratio_burst_vs_inproc": best.2 / best.0, "target": ">= 50 % of in process" }));
    handle.stop().unwrap();
}

/// Recorded, no target here (POLYGLOT-5 targets ≤ 512 KiB): the service's RSS
/// with 0, 1 and 8 stubs mounted, and 100 calls open on one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recorded_memory_per_mounted_child() {
    fn rss_kib() -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap()
    }
    let dir = tempfile::tempdir().unwrap();
    let spec = |i: usize| -> ChildSpec {
        format!("echo{i}=stdio:python3 -I {} --stdio --log {}", stub().display(), dir.path().join(format!("{i}.log")).display()).parse().unwrap()
    };
    let r0 = rss_kib();
    let mut kids = vec![RemoteChild::connect(spec(0), ChildOptions::default()).await.unwrap()];
    let r1 = rss_kib();
    for i in 1..8 {
        kids.push(RemoteChild::connect(spec(i), ChildOptions::default()).await.unwrap());
    }
    let r8 = rss_kib();
    let service = Arc::new(kids.iter().fold(DynamicHub::new("service"), |h, k| h.register(k.clone())));
    let t = HubTransport::anonymous(service);
    let mut open = vec![];
    for _ in 0..100 {
        let mut s = t.call(MethodRef::new("echo0", "count"), json!({ "to": 1000000, "delay_ms": 100 }));
        let _ = s.next().await;
        open.push(s);
    }
    let r100 = rss_kib();
    row(json!({ "row": "mem", "metric": "service RSS per mounted child (KiB)", "rss_0": r0, "first_child": r1 - r0,
        "per_child_of_8": (r8 - r0) as f64 / 8.0, "with_100_open_calls": r100 as i64 - r8 as i64, "open": kids[0].stats().open }));
    drop(open);
}
