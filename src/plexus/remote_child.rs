//! POLYGLOT-4 (spike) — the child seam's second implementation: an
//! activation in another process, mounted under a name, reached over stdio
//! as plexus-wire's spec says (01–05, 07, 11, and 12: the hop).
//!
//! **A prototype, thrown away** (branch `POLYGLOT-4`, tag
//! `archive/POLYGLOT-4`): POLYGLOT-5 builds the real one test-first. What it
//! holds is the shape — one `Link` per child (a writer task, a reader task
//! routing responses by id and items by subscription), the schema asked once
//! at connect and served from memory after, every call forwarded as
//! `{ns}.call {method, params, hop}` with the gate's verdict as `hop.limit`,
//! a dropped stream sent as `{ns}.call_unsub`, an item nobody asked for
//! dropped and counted, a dead child answering every open call with one
//! `child_unavailable` error item. No restart, no ws, no `--child` flag here.

use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::Stream;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

use super::auth::AuthContext;
use super::plexus::{Activation, ChildRouter, PlexusError};
use super::schema::PluginSchema;
use super::streaming::PlexusStream;
use super::types::{PlexusStreamItem, StreamMetadata};

/// `NAME=stdio:CMD ARGS…` (the spike splits on whitespace; POLYGLOT-5 uses
/// shell-words).
#[derive(Debug, Clone)]
pub struct ChildSpec {
    pub name: String,
    pub argv: Vec<String>,
}

impl FromStr for ChildSpec {
    type Err = ChildError;
    fn from_str(s: &str) -> Result<Self, ChildError> {
        let (name, rest) = s.split_once('=').ok_or_else(|| ChildError::Spec(format!("`{s}`: no `=`")))?;
        if name.is_empty() || name.contains('.') {
            return Err(ChildError::Spec(format!("`{name}`: a mount name is one non-empty segment")));
        }
        let cmd = rest.strip_prefix("stdio:").ok_or_else(|| ChildError::Spec(format!("`{rest}`: only stdio: in the spike")))?;
        let argv: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
        if argv.is_empty() {
            return Err(ChildError::Spec("no command".into()));
        }
        Ok(Self { name: name.to_string(), argv })
    }
}

/// How the service reaches its child.
#[derive(Debug, Clone)]
pub struct ChildOptions {
    /// The hop's principal: the service acting (spec/12). `service:<service>` on stdio
    /// when the service holds no key of its own.
    pub principal: String,
    /// A call's open, and the schema at connect.
    pub timeout: Duration,
}

impl Default for ChildOptions {
    fn default() -> Self {
        Self { principal: "service:service".into(), timeout: Duration::from_secs(5) }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChildError {
    #[error("child spec: {0}")]
    Spec(String),
    #[error("child {0}: {1}")]
    Start(String, String),
}

/// What the link has seen.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChildStats {
    pub open: usize,
    pub unasked: u64,
    pub calls: u64,
}

enum Pending {
    Call { reply: oneshot::Sender<Result<String, String>>, items: mpsc::UnboundedSender<PlexusStreamItem> },
}

struct State {
    pending: HashMap<u64, Pending>,
    subs: HashMap<String, mpsc::UnboundedSender<PlexusStreamItem>>,
    alive: bool,
}

struct Link {
    name: String,
    out: mpsc::UnboundedSender<Vec<u8>>,
    state: Mutex<State>,
    next_id: AtomicU64,
    unasked: AtomicU64,
    calls: AtomicU64,
    pid: Option<u32>,
    /// The child's own namespace, from its `_info`.
    ns: std::sync::OnceLock<String>,
}

fn meta(ns: &str) -> StreamMetadata {
    StreamMetadata::new(vec![ns.to_string()], super::context::PlexusContext::hash())
}

fn unavailable(name: &str, why: &str) -> PlexusStreamItem {
    PlexusStreamItem::Error {
        metadata: meta(name),
        message: format!("child {name} is unavailable: {why}"),
        code: Some("child_unavailable".into()),
        recoverable: true,
    }
}

impl Link {
    fn send(&self, frame: &Value) {
        let mut line = serde_json::to_vec(frame).unwrap_or_default();
        line.push(b'\n');
        let _ = self.out.send(line);
    }

    /// Open a call: the frame out, the subscription id back (the reader has
    /// already routed its items to `items` by then — spec/02 rule 1).
    async fn open(
        self: &Arc<Self>,
        method: String,
        params: Value,
        hop: Value,
        timeout: Duration,
    ) -> Result<(String, mpsc::UnboundedReceiver<PlexusStreamItem>), PlexusStreamItem> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        let (reply, answer) = oneshot::channel();
        {
            let mut st = self.state.lock().unwrap();
            if !st.alive {
                return Err(unavailable(&self.name, "the process has exited"));
            }
            st.pending.insert(id, Pending::Call { reply, items: tx });
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": format!("{}.call", self.ns()), "params": { "method": method, "params": params, "hop": hop } }));
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(Ok(sid))) => Ok((sid, rx)),
            Ok(Ok(Err(why))) => Err(unavailable(&self.name, &why)),
            Ok(Err(_)) => Err(unavailable(&self.name, "the process has exited")),
            Err(_) => {
                self.state.lock().unwrap().pending.remove(&id);
                Err(PlexusStreamItem::Error { metadata: meta(&self.name), message: format!("child {} did not open the call in {timeout:?}", self.name), code: Some("child_timeout".into()), recoverable: true })
            }
        }
    }

    fn ns(&self) -> String {
        self.ns.get().cloned().unwrap_or_else(|| self.name.clone())
    }

    fn unsubscribe(&self, sid: &str) {
        let live = self.state.lock().unwrap().subs.remove(sid).is_some();
        if live {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let raw: Value = serde_json::from_str(sid).unwrap_or(Value::Null);
            self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": format!("{}.call_unsub", self.ns()), "params": [raw] }));
        }
    }

    fn on_line(&self, line: &str) {
        let Ok(mut msg) = serde_json::from_str::<Value>(line) else {
            tracing::warn!(target: "plexus::child", child = %self.name, "unreadable line from the child");
            return;
        };
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            let pending = self.state.lock().unwrap().pending.remove(&id);
            if let Some(Pending::Call { reply, items }) = pending {
                match msg.get("result") {
                    Some(sid) => {
                        let key = sid.to_string();
                        self.state.lock().unwrap().subs.insert(key.clone(), items);
                        let _ = reply.send(Ok(key));
                    }
                    None => {
                        let _ = reply.send(Err(format!("refused the call: {}", msg.get("error").cloned().unwrap_or_default())));
                    }
                }
            }
            return; // an answer to an unsubscribe, or to nothing: nothing waits on it
        }
        let Some(p) = msg.get_mut("params") else { return };
        let item = p.get_mut("result").map(Value::take);
        let (Some(sid), Some(item)) = (p.get("subscription"), item) else { return };
        let key = sid.to_string();
        let terminal = matches!(item.get("type").and_then(Value::as_str), Some("done") | Some("error"));
        let mut st = self.state.lock().unwrap();
        let Some(tx) = st.subs.get(&key) else {
            drop(st);
            self.unasked.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(target: "plexus::child", child = %self.name, subscription = %key, "unasked item dropped");
            return;
        };
        let item = serde_json::from_value::<PlexusStreamItem>(item).unwrap_or_else(|e| PlexusStreamItem::Error {
            metadata: meta(&self.name),
            message: format!("child {} sent an unreadable item: {e}", self.name),
            code: Some("child_protocol".into()),
            recoverable: false,
        });
        let _ = tx.send(item);
        if terminal {
            st.subs.remove(&key);
        }
    }

    fn on_exit(&self, why: &str) {
        let mut st = self.state.lock().unwrap();
        st.alive = false;
        for (_, tx) in st.subs.drain() {
            let _ = tx.send(unavailable(&self.name, why));
        }
        for (_, Pending::Call { reply, .. }) in st.pending.drain() {
            let _ = reply.send(Err(why.to_string()));
        }
        tracing::warn!(target: "plexus::child", child = %self.name, "child gone: {why}");
    }
}

/// The stream the service hands its caller: the child's items, in order; dropped
/// before its end, it unsubscribes the child's call.
struct CallStream {
    rx: mpsc::UnboundedReceiver<PlexusStreamItem>,
    sid: String,
    link: Arc<Link>,
    over: bool,
}

impl Stream for CallStream {
    type Item = PlexusStreamItem;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.over {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(item)) => {
                if matches!(item, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. }) {
                    self.over = true;
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                self.over = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CallStream {
    fn drop(&mut self) {
        if !self.over {
            self.link.unsubscribe(&self.sid);
        }
    }
}

struct Inner {
    mount: String,
    child_ns: String,
    principal: String,
    timeout: Duration,
    schema: PluginSchema,
    link: Arc<Link>,
    timings: (f64, f64),
}

/// An activation in another process, mounted under `name`.
#[derive(Clone)]
pub struct RemoteChild {
    inner: Arc<Inner>,
}

impl RemoteChild {
    /// Spawn the child, ask its `_info` and its schema, and hold the link.
    pub async fn connect(spec: ChildSpec, opts: ChildOptions) -> Result<Self, ChildError> {
        let t0 = Instant::now();
        let start = |why: String| ChildError::Start(spec.name.clone(), why);
        let mut cmd = tokio::process::Command::new(&spec.argv[0]);
        cmd.args(&spec.argv[1..])
            .env_clear()
            .envs(["PATH", "HOME", "LANG"].iter().filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))))
            .env("PLEXUS_CHILD_NAME", &spec.name)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| start(format!("spawn: {e}")))?;
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let link = Arc::new(Link {
            name: spec.name.clone(),
            out,
            state: Mutex::new(State { pending: HashMap::new(), subs: HashMap::new(), alive: true }),
            next_id: AtomicU64::new(1),
            unasked: AtomicU64::new(0),
            calls: AtomicU64::new(0),
            pid: child.id(),
            ns: std::sync::OnceLock::new(),
        });
        // writer: everything queued, one write per wakeup (each line whole — spec/11)
        tokio::spawn(async move {
            while let Some(first) = out_rx.recv().await {
                let mut buf = first;
                while let Ok(more) = out_rx.try_recv() {
                    buf.extend_from_slice(&more);
                }
                if stdin.write_all(&buf).await.is_err() || stdin.flush().await.is_err() {
                    break;
                }
            }
        });
        // reader: responses by id, items by subscription
        let reader = Arc::clone(&link);
        tokio::spawn(async move {
            let mut lines = BufReader::with_capacity(1 << 16, stdout).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(l)) if !l.trim().is_empty() => reader.on_line(&l),
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
            let status = child.wait().await.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            reader.on_exit(&format!("the process exited ({status})"));
        });
        // stderr: the child's log, into the service's
        let name = spec.name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                tracing::debug!(target: "plexus::child", child = %name, "{l}");
            }
        });

        // _info → the child's namespace
        let hop = json!({ "principal": opts.principal, "for": [], "limit": null, "call": uuid::Uuid::new_v4().to_string() });
        let info = Self::ask(&link, "_info", None, &hop, opts.timeout).await.map_err(|e| start(e))?;
        let child_ns = info.get("backend").and_then(Value::as_str).ok_or_else(|| start("`_info` names no backend".into()))?.to_string();
        let _ = link.ns.set(child_ns.clone());
        let raw = Self::ask(&link, &format!("{child_ns}.schema"), Some(json!({})), &hop, opts.timeout).await.map_err(|e| start(e))?;
        let spawn_ms = t0.elapsed().as_secs_f64() * 1e3;
        let t1 = Instant::now();
        let mut schema: PluginSchema = serde_json::from_value(raw).map_err(|e| start(format!("its schema: {e}")))?;
        if schema.namespace != spec.name {
            tracing::info!(target: "plexus::child", child = %spec.name, declared = %schema.namespace, "mounted under its name, not the one it declares");
        }
        let requalify = |g: &String| match g.strip_prefix(&format!("{}.", schema.namespace)) {
            Some(m) => format!("{}.{m}", spec.name),
            None => format!("{}.{g}", spec.name),
        };
        schema.roles = schema.roles.iter().map(|(r, gs)| (r.clone(), gs.iter().map(requalify).collect())).collect();
        schema.namespace = spec.name.clone();
        let merge_ms = t1.elapsed().as_secs_f64() * 1e3;
        tracing::info!(target: "plexus::child", child = %spec.name, spawn_ms, merge_ms, "child mounted");
        Ok(Self {
            inner: Arc::new(Inner { mount: spec.name, child_ns, principal: opts.principal, timeout: opts.timeout, schema, link, timings: (spawn_ms, merge_ms) }),
        })
    }

    /// One unary call at connect: the first `data`'s content.
    async fn ask(link: &Arc<Link>, method: &str, params: Option<Value>, hop: &Value, timeout: Duration) -> Result<Value, String> {
        let (sid, mut rx) = if method == "_info" {
            // `_info` is its own JSON-RPC method (spec/07)
            let id = link.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::unbounded_channel();
            let (reply, answer) = oneshot::channel();
            link.state.lock().unwrap().pending.insert(id, Pending::Call { reply, items: tx });
            link.send(&json!({ "jsonrpc": "2.0", "id": id, "method": "_info", "params": null }));
            let sid = tokio::time::timeout(timeout, answer).await.map_err(|_| "no answer to `_info`".to_string())?.map_err(|_| "gone".to_string())??;
            (sid, rx)
        } else {
            link.open(method.to_string(), params.unwrap_or(json!({})), hop.clone(), timeout).await.map_err(|e| format!("{e:?}"))?
        };
        let _ = sid;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(PlexusStreamItem::Data { content, .. })) => Ok(content),
            other => Err(format!("{method}: {other:?}")),
        }
    }

    pub fn stats(&self) -> ChildStats {
        let l = &self.inner.link;
        ChildStats { open: l.state.lock().unwrap().subs.len(), unasked: l.unasked.load(Ordering::Relaxed), calls: l.calls.load(Ordering::Relaxed) }
    }

    pub fn pid(&self) -> Option<u32> {
        self.inner.link.pid
    }

    /// (spawn → schema, the schema's merge) in ms.
    pub fn mount_timings(&self) -> (f64, f64) {
        self.inner.timings
    }

    /// The hop (spec/12): the service acts, the caller is named `for`, the
    /// gate's verdict is the limit. Nothing of the caller's credential.
    fn hop(&self, method: &str, auth: Option<&AuthContext>) -> Value {
        let reach = super::grant_gate::current_reach();
        let grant = match reach.grant() {
            Some(g) => match g.as_str().strip_prefix(&format!("{}.", self.inner.mount)) {
                Some(m) => format!("{}.{m}", self.inner.child_ns),
                None => g.as_str().to_string(),
            },
            None => format!("{}.{method}", self.inner.child_ns),
        };
        let held_on: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        let r#for: Vec<String> = auth.and_then(|a| a.principal()).map(|p| p.to_string()).into_iter().collect();
        json!({ "principal": self.inner.principal, "for": r#for, "limit": { "grant": grant, "held_on": held_on }, "call": uuid::Uuid::new_v4().to_string() })
    }

    fn schema_stream(&self, params: &Value) -> PlexusStream {
        let content = match params.get("method").and_then(Value::as_str) {
            Some(m) => match self.inner.schema.methods.iter().find(|x| x.name == m) {
                Some(ms) => serde_json::to_value(ms).unwrap_or_default(),
                None => {
                    let e = PlexusStreamItem::Error { metadata: meta(&self.inner.mount), message: format!("Method '{m}' not found"), code: Some("-32602".into()), recoverable: false };
                    return Box::pin(futures::stream::iter([e]));
                }
            },
            None => serde_json::to_value(&self.inner.schema).unwrap_or_default(),
        };
        let ns = self.inner.mount.clone();
        Box::pin(futures::stream::iter([
            PlexusStreamItem::Data { metadata: meta(&ns), content_type: format!("{ns}.schema"), content },
            PlexusStreamItem::Done { metadata: meta(&ns) },
        ]))
    }
}

#[async_trait]
impl Activation for RemoteChild {
    type Methods = crate::activations::health::HealthMethod; // the spike's stand-in: a child's methods are data

    fn namespace(&self) -> &str {
        &self.inner.mount
    }
    fn version(&self) -> &str {
        &self.inner.schema.version
    }
    fn description(&self) -> &str {
        &self.inner.schema.description
    }
    fn methods(&self) -> Vec<&str> {
        self.inner.schema.methods.iter().map(|m| m.name.as_str()).collect()
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>, _raw: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        if method == "schema" {
            return Ok(self.schema_stream(&params));
        }
        if !self.inner.schema.methods.iter().any(|m| m.name == method) {
            return Err(PlexusError::MethodNotFound { activation: self.inner.mount.clone(), method: method.to_string() });
        }
        let hop = self.hop(method, auth);
        let path = format!("{}.{method}", self.inner.child_ns);
        match self.inner.link.open(path, params, hop, self.inner.timeout).await {
            Ok((sid, rx)) => Ok(Box::pin(CallStream { rx, sid, link: Arc::clone(&self.inner.link), over: false })),
            Err(item) => Ok(Box::pin(futures::stream::iter([item]))),
        }
    }

    fn into_rpc_methods(self) -> jsonrpsee::Methods {
        jsonrpsee::Methods::new()
    }

    fn plugin_schema(&self) -> PluginSchema {
        self.inner.schema.clone()
    }
}

#[async_trait]
impl ChildRouter for RemoteChild {
    fn router_namespace(&self) -> &str {
        &self.inner.mount
    }
    async fn router_call(&self, method: &str, params: Value, auth: Option<&AuthContext>, raw: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        Activation::call(self, method, params, auth, raw).await
    }
    async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
        None
    }
    fn router_schema(&self) -> Option<PluginSchema> {
        Some(self.inner.schema.clone())
    }
}
