//! POLYGLOT-5 — what tests/remote_child.rs and tests/remote_child_perf.rs
//! share: plexus-wire's reference child (`stub_child.py`) on stdio or on a
//! WebSocket, a gated service mounting it beside an in-process Rust echo, a
//! test key, and the readers of the child's log.
#![allow(dead_code)]

use async_stream::stream;
use base64::Engine;
use futures::stream::{Stream, StreamExt};
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::{AuthContext, ChildOptions, ChildSpec, Gate, HubTransport, Membership, Memberships, RemoteChild, Resolve, RoleTable, ScopeRef};
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
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

/// The in-process Rust echo the child is measured and compared against.
#[derive(Clone)]
pub struct RsechoActivation;

#[plexus_macros::activation(version = "1.0.0", description = "in-process echo", roles(viewer = ["echo", "count"]))]
impl RsechoActivation {
    /// Say `text`, `times` times.
    #[plexus_macros::method]
    pub async fn echo(&self, text: String, times: u64) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! { for _ in 0..times { yield EchoEvent::Said { text: text.clone() }; } }
    }

    /// 1..=to.
    #[plexus_macros::method]
    pub async fn count(&self, to: u64) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! { for n in 1..=to { yield EchoEvent::N { n }; } }
    }
}

/// The same surface under the namespace `echo`, so one macro-emitted client
/// (`EchoClient`) calls it in process and the stub mounted as `echo` alike.
#[derive(Clone)]
pub struct EchoActivation;

#[plexus_macros::activation(version = "1.0.0", description = "in-process echo, as echo", roles(viewer = ["echo", "count"]))]
impl EchoActivation {
    /// Say `text`, `times` times.
    #[plexus_macros::method]
    pub async fn echo(&self, text: String, times: u64) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! { for _ in 0..times { yield EchoEvent::Said { text: text.clone() }; } }
    }

    /// 1..=to.
    #[plexus_macros::method]
    pub async fn count(&self, to: u64) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! { for n in 1..=to { yield EchoEvent::N { n }; } }
    }
}

pub const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const NOBODY: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const SESSION_SECRET: &str = "mgs_SESSIONSECRET0123456789";
pub const KEY_SECRET: &str = "plexus-key.PROOFSECRET0123456789";

#[derive(Default)]
pub struct Members(pub Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}
pub struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

/// A caller whose context carries a planted session id and key proof: what
/// must never reach a child.
pub fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), SESSION_SECRET, vec![], json!({ "session_key": KEY_SECRET, "token": KEY_SECRET }))
}

pub fn stub() -> PathBuf {
    std::env::var_os("PLEXUS_STUB_CHILD").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-wire/conformance/examples/stub_child.py")
    })
}

/// The test service's key: a seed in a 0600 file, as synapse keeps one.
pub struct TestKey {
    pub path: PathBuf,
    pub principal: String,
}

pub fn test_key(dir: &Path, name: &str, seed: [u8; 32]) -> TestKey {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("{name}.key"));
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode(seed)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let hex: String = public.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    TestKey { path, principal: format!("key:{hex}") }
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The stub served on a WebSocket, trusting `trust`; killed on drop.
pub struct WsStub {
    pub child: std::process::Child,
    pub port: u16,
    pub log: PathBuf,
}

impl Drop for WsStub {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn ws_stub(dir: &Path, trust: &str, extra: &[&str]) -> WsStub {
    let port = free_port();
    let log = dir.join(format!("ws-{port}.log"));
    let child = std::process::Command::new("python3")
        .arg("-I")
        .arg(stub())
        .args(["--ws", &port.to_string(), "--trust", trust, "--log", &log.display().to_string()])
        .args(extra)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&log).unwrap_or_default().contains("\"listening\"") {
        assert!(Instant::now() < deadline, "the ws stub never listened");
        std::thread::sleep(Duration::from_millis(10));
    }
    WsStub { child, port, log }
}

pub enum Via {
    Stdio,
    Ws,
}

pub struct Rig {
    pub service: Arc<DynamicHub>,
    pub child: RemoteChild,
    pub log: PathBuf,
    pub members: Arc<Members>,
    pub gate: Gate,
    pub key: TestKey,
    pub ws: Option<WsStub>,
    pub dir: tempfile::TempDir,
}

pub fn stdio_spec(name: &str, log: &Path, extra: &str) -> ChildSpec {
    format!("{name}=stdio:python3 -I {} --stdio --log {} {extra}", stub().display(), log.display()).parse().unwrap()
}

/// A gated service `service` of `rsecho` (in process) and the stub mounted
/// as `echo` (on stdio, or dialed on a WebSocket with the service's key);
/// ADA views everywhere, NOBODY holds nothing.
pub async fn rig_with(via: Via, opts: ChildOptions, extra: &str) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let key = test_key(dir.path(), "service", [9u8; 32]);
    let (spec, log, ws, opts) = match via {
        Via::Stdio => {
            let log = dir.path().join("child.log");
            (stdio_spec("echo", &log, extra), log, None, opts)
        }
        Via::Ws => {
            let extras: Vec<&str> = extra.split_whitespace().collect();
            let s = ws_stub(dir.path(), &key.principal, &extras);
            let spec: ChildSpec = format!("echo=ws://127.0.0.1:{}", s.port).parse().unwrap();
            let log = s.log.clone();
            (spec, log, Some(s), ChildOptions { key: Some(key.path.clone()), ..opts })
        }
    };
    let child = RemoteChild::connect(spec, opts).await.expect("the stub mounts");
    let plain = || DynamicHub::new("service").register(RsechoActivation).register(child.clone());
    let members = Arc::new(Members::default());
    members.0.lock().unwrap().push(Membership { principal: ADA.parse().unwrap(), role: plexus_auth_core::RoleName::new("viewer"), scope: ScopeRef::parse("*") });
    let declared = plain().declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let gate = Gate::new(members.clone(), Arc::new(roles), Arc::new(Everywhere));
    Rig { service: Arc::new(plain().with_gate(Arc::new(gate.clone()))), child, log, members, gate, key, ws, dir }
}

pub async fn rig(via: Via) -> Rig {
    rig_with(via, ChildOptions::default(), "").await
}

pub async fn collect(t: &HubTransport, ns: &'static str, m: &'static str, p: Value) -> Vec<StreamItem> {
    let mut s = t.call(MethodRef::new(ns, m), p);
    let mut out = vec![];
    while let Some(i) = s.next().await {
        out.push(i.expect("no transport error in memory"));
    }
    out
}

/// The service's own stream for a call — `PlexusStreamItem`s, every field
/// kept (the client's `StreamItem` keeps only the four it knows).
pub async fn route(r: &Rig, caller: &str, method: &str, p: Value) -> Vec<Value> {
    match r.service.route_with_ctx(method, p, Some(&who(caller)), None).await {
        Ok(s) => s.map(|i| serde_json::to_value(i).unwrap()).collect().await,
        Err(e) => vec![plexus_core::plexus::plexus::error_item("service", &e)],
    }
}

pub fn kinds(items: &[StreamItem]) -> Vec<&'static str> {
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

pub fn types(items: &[Value]) -> Vec<String> {
    items.iter().map(|i| i["type"].as_str().unwrap_or("?").to_string()).collect()
}

pub fn child_log(log: &Path) -> Vec<Value> {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Wait (≤ `within`) for the child's log to hold an event `ev` after `since`
/// (unix ns, the child's clock); its time.
pub async fn child_event(log: &Path, ev: &str, since: u128, within: Duration) -> Option<u128> {
    let deadline = Instant::now() + within;
    loop {
        let hit = child_log(log).into_iter().filter(|e| e["ev"] == ev).filter_map(|e| e["t"].as_u64()).map(u128::from).find(|t| *t >= since);
        if hit.is_some() || Instant::now() >= deadline {
            return hit;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

pub fn unix_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

pub fn pct(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

pub fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap()
}

/// Serve `service` on a WebSocket (jsonrpsee, no gate on the socket — the
/// service's own), for callers that read the wire.
pub async fn serve(service: Arc<DynamicHub>) -> (std::net::SocketAddr, jsonrpsee::server::ServerHandle) {
    let module = DynamicHub::arc_into_rpc_module(service).unwrap();
    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    (addr, server.start(module))
}
