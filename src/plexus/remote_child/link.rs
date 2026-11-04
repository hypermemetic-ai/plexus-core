//! One connection to a child — its frames out, its answers routed back —
//! and the supervisor that starts it, notices it gone and starts it again.
//!
//! A [`Conn`] is one process (stdio) or one socket (ws): a writer task that
//! drains everything queued into one write per wakeup (spec/11), a reader
//! that routes a response by `id` to the call that opened it (registering
//! the subscription before the next message is read, so an item can never
//! beat its id — spec/02) and an item by `subscription` to that call's
//! bounded channel, and — when the far side goes — one `child_unavailable`
//! to every call it held. A [`Shared`] outlives its connections: it keeps
//! the schema's hash, the counters and the restart window.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, Notify};

use super::spec::{ChildOptions, ChildSpec};
use crate::plexus::types::{PlexusStreamItem, StreamMetadata};
use plexus_client::RemoteError;

/// A subscription id as the child spelled it (its JSON text: `4`, `"a"`).
pub(super) type SubKey = String;

pub(super) fn meta(name: &str) -> StreamMetadata {
    StreamMetadata::new(vec![name.to_string()], crate::plexus::context::PlexusContext::hash())
}

/// `child_unavailable` (spec/12 rule 5): one error, and the end.
pub(super) fn unavailable(name: &str, why: &str) -> PlexusStreamItem {
    PlexusStreamItem::error(meta(name), RemoteError::ChildUnavailable { child: name.into(), reason: why.into() }, true)
}

/// `child_timeout`: the child did not open the call in the service's time.
pub(super) fn timed_out(name: &str, timeout: Duration) -> PlexusStreamItem {
    let error = RemoteError::ChildTimeout { child: name.into(), timeout_ms: timeout.as_millis() as u64 };
    let mut item = PlexusStreamItem::error(meta(name), error, true);
    if let PlexusStreamItem::Error { message, .. } = &mut item {
        *message = format!("child {name} did not open the call in {timeout:?}");
    }
    item
}

/// `too_many_calls` (spec/05, 09): as a connection's limit answers.
pub(super) fn too_many(name: &str, max: usize) -> PlexusStreamItem {
    PlexusStreamItem::error(meta(name), RemoteError::TooManyCalls { max: max as u64, child: Some(name.into()) }, true)
}

/// A call the child refused at the JSON-RPC layer (`{code, message,
/// data?}`): its `data` when that is a typed [`RemoteError`] (RETURNS-6),
/// else what its code says; spec/05's `message` and `code` as it sent them.
fn refused(name: &str, e: &Value) -> PlexusStreamItem {
    let code = e.get("code").map(|c| match c {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    let message = e.get("message").and_then(Value::as_str).unwrap_or("the child refused the call").to_string();
    let error = e
        .get("data")
        .and_then(|d| serde_json::from_value::<RemoteError>(d.clone()).ok())
        .unwrap_or_else(|| match e.get("code").and_then(Value::as_i64) {
            Some(-32602) => RemoteError::InvalidParams {
                param: None,
                problem: plexus_client::ParamProblem::Malformed { detail: message.clone() },
            },
            Some(-32001) => RemoteError::Unauthenticated,
            _ => RemoteError::Execution { message: message.clone() },
        });
    let fields = crate::plexus::types::spec_fields(&error);
    PlexusStreamItem::Error { metadata: meta(name), message, code, recoverable: false, error, fields }
}

/// Counters that outlive a connection.
#[derive(Default)]
pub(super) struct Counters {
    pub unasked: AtomicU64,
    pub calls: AtomicU64,
    pub restarts: AtomicU64,
    pub open: AtomicUsize,
}

/// How a call's open failed.
pub(super) enum OpenFail {
    /// The connection went before the child answered.
    Gone(String),
    /// The child answered the open with a JSON-RPC error.
    Refused(Value),
}

struct Opening {
    reply: oneshot::Sender<Result<SubKey, OpenFail>>,
    items: mpsc::Sender<PlexusStreamItem>,
}

/// How long after its `true` an unsubscribed call's late item is still the
/// cancel's tail: spec/04 lets an item already in flight land just after
/// the response (the kit allows 50 ms).
const TAIL: Duration = Duration::from_millis(250);

#[derive(Default)]
struct Routes {
    pending: HashMap<u64, Opening>,
    subs: HashMap<SubKey, mpsc::Sender<PlexusStreamItem>>,
    /// Unsubscribes sent and not yet answered, and those answered within
    /// [`TAIL`]: their late items are the cancel's tail, dropped quietly
    /// (not "unasked").
    closing: HashMap<u64, SubKey>,
    closing_subs: HashSet<SubKey>,
    answered: VecDeque<(Instant, SubKey)>,
    /// Opens past their timeout: a late answer is unsubscribed at once.
    abandoned: HashSet<u64>,
}

impl Routes {
    /// Forget the cancels answered more than [`TAIL`] ago.
    fn expire_tails(&mut self, now: Instant) {
        while self.answered.front().is_some_and(|(t, _)| now.duration_since(*t) >= TAIL) {
            if let Some((_, key)) = self.answered.pop_front() {
                self.closing_subs.remove(&key);
            }
        }
    }
}

/// One connection to the child.
pub(super) struct Conn {
    pub name: String,
    pub pid: Option<u32>,
    /// The child's own namespace (its `_info`'s `backend`).
    pub ns: OnceLock<String>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    routes: Mutex<Routes>,
    next_id: AtomicU64,
    alive: AtomicBool,
    /// Asked to end (the service let go of the child, or refused its schema).
    pub shutdown: Notify,
    buffer: usize,
    counters: Arc<Counters>,
}

/// One message, read in one pass: a notification's item stays raw until
/// its call is known (then it is read once, as the item).
#[derive(Deserialize)]
struct Msg<'a> {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default, borrow)]
    result: Option<&'a RawValue>,
    #[serde(default)]
    error: Option<Value>,
    #[serde(default, borrow)]
    method: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    params: Option<Notif<'a>>,
}

#[derive(Deserialize)]
struct Notif<'a> {
    #[serde(default)]
    subscription: Option<Value>,
    #[serde(default, borrow)]
    result: Option<&'a RawValue>,
}

/// A message whose `params` are not an object (a request with positional
/// params): read loosely, only to answer it.
#[derive(Deserialize)]
struct Loose<'a> {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default, borrow)]
    method: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Kind<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
}

impl Conn {
    pub(super) fn new(name: &str, pid: Option<u32>, out: mpsc::UnboundedSender<Vec<u8>>, buffer: usize, counters: Arc<Counters>) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            pid,
            ns: OnceLock::new(),
            out,
            routes: Mutex::new(Routes::default()),
            next_id: AtomicU64::new(1),
            alive: AtomicBool::new(true),
            shutdown: Notify::new(),
            buffer,
            counters,
        })
    }

    pub(super) fn alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub(super) fn ns(&self) -> &str {
        self.ns.get().map(String::as_str).unwrap_or(&self.name)
    }

    fn send(&self, frame: &Value) {
        let _ = self.out.send(serde_json::to_vec(frame).unwrap_or_default());
    }

    /// Open a call: `method` with `params` (a `{ns}.call`'s params, or
    /// `_info`'s null); the subscription id back within `timeout`, its items
    /// already routed to the receiver.
    pub(super) async fn open(&self, method: &str, params: Value, timeout: Duration) -> Result<(SubKey, mpsc::Receiver<PlexusStreamItem>), PlexusStreamItem> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(self.buffer);
        let (reply, answer) = oneshot::channel();
        {
            let mut r = self.routes.lock().unwrap();
            if !self.alive() {
                return Err(unavailable(&self.name, "the connection has closed"));
            }
            r.pending.insert(id, Opening { reply, items: tx });
        }
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(Ok(key))) => Ok((key, rx)),
            Ok(Ok(Err(OpenFail::Gone(why)))) => Err(unavailable(&self.name, &why)),
            Ok(Err(_)) => Err(unavailable(&self.name, "the connection closed before the call opened")),
            Ok(Ok(Err(OpenFail::Refused(e)))) => Err(refused(&self.name, &e)),
            Err(_) => {
                let mut r = self.routes.lock().unwrap();
                if r.pending.remove(&id).is_some() {
                    r.abandoned.insert(id);
                }
                Err(timed_out(&self.name, timeout))
            }
        }
    }

    /// The caller let go of `key` before its end: forget it, and tell the
    /// child (`{ns}.call_unsub [sid]`, spec/04).
    pub(super) fn unsubscribe(&self, key: &str) {
        let id = {
            let mut r = self.routes.lock().unwrap();
            if r.subs.remove(key).is_none() || !self.alive() {
                return;
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            r.closing.insert(id, key.to_string());
            r.closing_subs.insert(key.to_string());
            id
        };
        let method = serde_json::to_string(&format!("{}.call_unsub", self.ns())).unwrap_or_default();
        let frame = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":{method},"params":[{key}]}}"#);
        let _ = self.out.send(frame.into_bytes());
    }

    /// How many subscriptions are routed now.
    pub(super) fn routed(&self) -> usize {
        self.routes.lock().unwrap().subs.len()
    }

    /// One message from the child.
    pub(super) async fn on_message(&self, raw: &[u8]) {
        let msg: Msg<'_> = match serde_json::from_slice(raw) {
            Ok(m) => m,
            Err(e) => match serde_json::from_slice::<Loose<'_>>(raw) {
                Ok(Loose { id: Some(id), method: Some(method) }) => return self.refuse_request(id, &method),
                _ => {
                    tracing::warn!(target: "plexus::child", child = %self.name, "an unreadable message from the child: {e}");
                    return;
                }
            },
        };
        if let Some(method) = msg.method {
            if let Some(id) = msg.id {
                return self.refuse_request(id, &method);
            }
            match msg.params {
                Some(Notif { subscription: Some(sub), result: Some(item) }) => self.route(sub.to_string(), item).await,
                _ => tracing::warn!(target: "plexus::child", child = %self.name, %method, "a notification without subscription and result"),
            }
            return;
        }
        let Some(id) = msg.id.as_ref().and_then(Value::as_u64) else { return };
        let mut r = self.routes.lock().unwrap();
        if let Some(open) = r.pending.remove(&id) {
            match (msg.result, msg.error) {
                (Some(sid), _) => {
                    let key = match serde_json::from_str::<Value>(sid.get()) {
                        Ok(v) => v.to_string(),
                        Err(_) => sid.get().to_string(),
                    };
                    r.subs.insert(key.clone(), open.items);
                    let _ = open.reply.send(Ok(key));
                }
                (None, e) => {
                    let _ = open.reply.send(Err(OpenFail::Refused(e.unwrap_or_else(|| json!({ "message": "an answer with neither result nor error" })))));
                }
            }
        } else if let Some(key) = r.closing.remove(&id) {
            // Answered: an item still in flight is the tail for TAIL more.
            let now = Instant::now();
            r.expire_tails(now);
            r.answered.push_back((now, key));
        } else if r.abandoned.remove(&id) {
            // A call opened after its caller was told `child_timeout`: stop it.
            if let Some(sid) = msg.result.and_then(|s| serde_json::from_str::<Value>(s.get()).ok()) {
                let key = sid.to_string();
                let uid = self.next_id.fetch_add(1, Ordering::Relaxed);
                r.closing.insert(uid, key.clone());
                r.closing_subs.insert(key.clone());
                drop(r);
                let method = serde_json::to_string(&format!("{}.call_unsub", self.ns())).unwrap_or_default();
                let _ = self.out.send(format!(r#"{{"jsonrpc":"2.0","id":{uid},"method":{method},"params":[{key}]}}"#).into_bytes());
            }
        }
    }

    /// A child asks its service nothing (spec/12): answered, not served.
    fn refuse_request(&self, id: Value, method: &str) {
        tracing::warn!(target: "plexus::child", child = %self.name, %method, "a request from the child refused");
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "a service answers no requests from its child" } }));
    }

    async fn route(&self, key: SubKey, raw: &RawValue) {
        let tx = {
            let mut r = self.routes.lock().unwrap();
            match r.subs.get(&key) {
                Some(tx) => tx.clone(),
                None => {
                    r.expire_tails(Instant::now());
                    if !r.closing_subs.contains(&key) {
                        drop(r);
                        self.counters.unasked.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(target: "plexus::child", child = %self.name, subscription = %key, "unasked item dropped");
                    }
                    return;
                }
            }
        };
        // RETURNS-36: a peer on plexus-wire's spec as main wrote it is read
        // into 0.8's shape (`peer::item`) when — only when — it does not
        // read as 0.8.
        let parsed = serde_json::from_str::<PlexusStreamItem>(raw.get()).or_else(|e| {
            super::peer::item(raw.get(), &self.name)
                .and_then(|v| serde_json::from_value::<PlexusStreamItem>(v).ok())
                .ok_or(e)
        });
        let item = match parsed {
            Ok(item) => item,
            Err(e) => {
                let kind = serde_json::from_str::<Kind<'_>>(raw.get()).map(|k| k.kind.into_owned()).unwrap_or_default();
                if kind != "error" {
                    // An item kind this service does not know (spec/03: a
                    // reader skips it) — or one that does not read at all.
                    tracing::debug!(target: "plexus::child", child = %self.name, subscription = %key, %kind, "an item kind not relayed: {e}");
                    return;
                }
                // RETURNS-36 (review #4): an error item is the call's end
                // (spec/03); skipped, the call would wait for an end that
                // never comes. It ends here, naming what could not be read,
                // and the child is told to stop.
                tracing::warn!(target: "plexus::child", child = %self.name, subscription = %key, "an error item not read: {e}");
                self.unsubscribe(&key);
                let error = plexus_client::RemoteError::Execution {
                    message: format!("child {} sent an error item this service could not read: {e}", self.name),
                };
                PlexusStreamItem::error(meta(&self.name), error, false)
            }
        };
        if matches!(item, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. }) {
            self.routes.lock().unwrap().subs.remove(&key);
        }
        match tx.try_send(item) {
            Ok(()) => {}
            // The caller has not read the call's buffer: wait for it
            // (lossless; the child's other calls wait behind it).
            Err(mpsc::error::TrySendError::Full(item)) => {
                let _ = tx.send(item).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// The far side is gone: every open call gets one `child_unavailable`.
    pub(super) fn on_gone(&self, why: &str) {
        let (subs, pending) = {
            let mut r = self.routes.lock().unwrap();
            self.alive.store(false, Ordering::Release);
            r.closing.clear();
            r.closing_subs.clear();
            r.answered.clear();
            r.abandoned.clear();
            (std::mem::take(&mut r.subs), std::mem::take(&mut r.pending))
        };
        for (_, tx) in subs {
            match tx.try_send(unavailable(&self.name, why)) {
                Err(mpsc::error::TrySendError::Full(item)) => {
                    tokio::spawn(async move {
                        let _ = tx.send(item).await;
                    });
                }
                _ => {}
            }
        }
        for (_, open) in pending {
            let _ = open.reply.send(Err(OpenFail::Gone(why.to_string())));
        }
    }
}

/// Read newline-delimited messages from `r`, one wakeup per read: every
/// whole line in the buffer is routed before the next read.
pub(super) async fn read_lines<R: AsyncRead + Unpin>(conn: &Conn, r: R) {
    let mut r = BufReader::with_capacity(1 << 17, r);
    let mut carry: Vec<u8> = Vec::new();
    loop {
        let buf = match r.fill_buf().await {
            Ok(b) if !b.is_empty() => b,
            _ => break,
        };
        let n = buf.len();
        let mut start = 0;
        while let Some(i) = buf[start..].iter().position(|b| *b == b'\n') {
            let end = start + i;
            if carry.is_empty() {
                let line = &buf[start..end];
                if line.iter().any(|b| !b.is_ascii_whitespace()) {
                    conn.on_message(line).await;
                }
            } else {
                carry.extend_from_slice(&buf[start..end]);
                let line = std::mem::take(&mut carry);
                if line.iter().any(|b| !b.is_ascii_whitespace()) {
                    conn.on_message(&line).await;
                }
            }
            start = end + 1;
        }
        carry.extend_from_slice(&buf[start..]);
        r.consume(n);
    }
}

/// The writer: everything queued, one write per wakeup, each line whole.
pub(super) async fn write_lines<W: tokio::io::AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(first) = rx.recv().await {
        let mut buf = first;
        buf.push(b'\n');
        while let Ok(more) = rx.try_recv() {
            buf.extend_from_slice(&more);
            buf.push(b'\n');
        }
        if w.write_all(&buf).await.is_err() || w.flush().await.is_err() {
            break;
        }
    }
}

/// When the child was mounted, how long each step took.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MountTimings {
    /// Spawn (or dial) → its `_info` answered.
    pub spawn_ms: f64,
    /// `_info` → its schema answered.
    pub schema_ms: f64,
    /// The schema requalified under the mount name and kept.
    pub merge_ms: f64,
}

struct LinkState {
    conn: Option<Arc<Conn>>,
    down_since: Option<Instant>,
    why: String,
    window: VecDeque<Instant>,
    /// Never again (a restart published another schema): the reason.
    dead: Option<String>,
}

/// The child across its connections.
pub(super) struct Shared {
    pub spec: ChildSpec,
    pub opts: ChildOptions,
    pub name: String,
    /// The hop's `principal`.
    pub principal: String,
    pub counters: Arc<Counters>,
    state: Mutex<LinkState>,
    dial: tokio::sync::Mutex<()>,
    /// The mounted schema's hash, as the child published it.
    pub mounted_hash: OnceLock<String>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        if let Ok(st) = self.state.lock() {
            if let Some(c) = &st.conn {
                c.shutdown.notify_one();
            }
        }
    }
}

/// The hash a child's schema is compared by across restarts.
pub(super) fn schema_hash(raw: &Value) -> String {
    match raw.get("hash").and_then(Value::as_str) {
        Some(h) => h.to_string(),
        None => raw.get("methods").map(Value::to_string).unwrap_or_default(),
    }
}

impl Shared {
    pub(super) fn new(spec: ChildSpec, opts: ChildOptions, principal: String) -> Arc<Self> {
        Arc::new(Self {
            name: spec.name().to_string(),
            spec,
            opts,
            principal,
            counters: Arc::new(Counters::default()),
            state: Mutex::new(LinkState { conn: None, down_since: None, why: String::new(), window: VecDeque::new(), dead: None }),
            dial: tokio::sync::Mutex::new(()),
            mounted_hash: OnceLock::new(),
        })
    }

    pub(super) fn current(&self) -> Option<Arc<Conn>> {
        self.state.lock().unwrap().conn.clone()
    }

    pub(super) fn install(&self, conn: Arc<Conn>) {
        self.state.lock().unwrap().conn = Some(conn);
    }

    /// The service asks for itself (the mount): no caller, no verdict.
    fn own_hop(&self) -> Value {
        json!({ "principal": self.principal, "for": [], "limit": null, "call": uuid::Uuid::new_v4().to_string() })
    }

    /// Start (or dial) the child and ask its `_info` and its schema.
    pub(super) async fn connect_once(self: &Arc<Self>) -> Result<(Arc<Conn>, Value, MountTimings), String> {
        let t0 = Instant::now();
        let conn = match &self.spec {
            ChildSpec::Stdio { argv, .. } => self.spawn_stdio(argv)?,
            ChildSpec::Ws { url, .. } => self.dial_ws(url).await?,
        };
        let asked = async {
            let info = ask(&conn, "_info", Value::Null, self.opts.timeout).await.map_err(|e| format!("`_info`: {e}"))?;
            let ns = info.get("backend").and_then(Value::as_str).ok_or("its `_info` names no backend")?.to_string();
            let _ = conn.ns.set(ns.clone());
            let t1 = Instant::now();
            let params = json!({ "method": format!("{ns}.schema"), "params": {}, "hop": self.own_hop() });
            let schema = ask(&conn, &format!("{ns}.call"), params, self.opts.timeout).await.map_err(|e| format!("its schema: {e}"))?;
            Ok::<_, String>((schema, t1))
        };
        match asked.await {
            Ok((schema, t1)) => {
                let t = MountTimings { spawn_ms: (t1 - t0).as_secs_f64() * 1e3, schema_ms: t1.elapsed().as_secs_f64() * 1e3, merge_ms: 0.0 };
                Ok((conn, schema, t))
            }
            Err(why) => {
                conn.shutdown.notify_one();
                Err(why)
            }
        }
    }

    fn spawn_stdio(self: &Arc<Self>, argv: &[String]) -> Result<Arc<Conn>, String> {
        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env_clear()
            .envs(["PATH", "HOME", "LANG"].iter().map(|k| k.to_string()).chain(self.opts.env.iter().cloned()).filter_map(|k| std::env::var(&k).ok().map(|v| (k, v))))
            .env("PLEXUS_CHILD_NAME", &self.name)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("spawning `{}`: {e}", argv[0]))?;
        let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
            return Err("its pipes were not opened".into());
        };
        let (out, out_rx) = mpsc::unbounded_channel();
        let conn = Conn::new(&self.name, child.id(), out, self.opts.buffer, Arc::clone(&self.counters));
        tokio::spawn(write_lines(stdin, out_rx));
        let reader = Arc::clone(&conn);
        let shared = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::select! {
                _ = read_lines(&reader, stdout) => {}
                _ = reader.shutdown.notified() => {
                    let _ = child.start_kill();
                }
            }
            let status = child.wait().await.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            gone(&shared, &reader, &format!("the process exited ({status})"));
        });
        let name = self.name.clone();
        tokio::spawn(async move {
            let span = tracing::info_span!(target: "plexus::child", "plexus::child", name = %name);
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let _e = span.enter();
                tracing::info!(target: "plexus::child", child = %name, "{l}");
            }
        });
        Ok(conn)
    }

    #[cfg(feature = "child-ws")]
    async fn dial_ws(self: &Arc<Self>, url: &str) -> Result<Arc<Conn>, String> {
        super::ws::dial(self, url).await
    }

    #[cfg(not(feature = "child-ws"))]
    async fn dial_ws(self: &Arc<Self>, _url: &str) -> Result<Arc<Conn>, String> {
        Err("a WebSocket child needs plexus-core's `child-ws` feature".into())
    }

    /// The connection `conn` is gone; the next call starts another.
    pub(super) fn lost(&self, conn: &Arc<Conn>, why: &str) {
        let mut st = self.state.lock().unwrap();
        if st.conn.as_ref().is_some_and(|c| Arc::ptr_eq(c, conn)) {
            st.conn = None;
            st.down_since = Some(Instant::now());
            st.why = why.to_string();
            drop(st);
            tracing::warn!(target: "plexus::child", child = %self.name, "child gone: {why}");
        }
    }

    /// A live connection, starting the child again if it died — within the
    /// backoff, and never past `per_minute` restarts a minute.
    pub(super) async fn ensure(self: &Arc<Self>) -> Result<Arc<Conn>, PlexusStreamItem> {
        if let Some(c) = self.live()? {
            return Ok(c);
        }
        let _g = self.dial.lock().await;
        if let Some(c) = self.live()? {
            return Ok(c);
        }
        let b = self.opts.backoff;
        let wait = {
            let mut st = self.state.lock().unwrap();
            let now = Instant::now();
            while st.window.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
                st.window.pop_front();
            }
            if st.window.len() >= b.per_minute {
                let next = st.window.front().map(|t| Duration::from_secs(60).saturating_sub(now.duration_since(*t))).unwrap_or_default();
                return Err(unavailable(&self.name, &format!("{} (restarted {} times in the last minute; the next restart in {:.1} s)", st.why, st.window.len(), next.as_secs_f64())));
            }
            let due = st.down_since.unwrap_or(now) + b.delay(st.window.len());
            due.saturating_duration_since(now)
        };
        if wait > self.opts.timeout {
            let why = self.state.lock().unwrap().why.clone();
            return Err(unavailable(&self.name, &format!("{why} (restarting in {:.1} s)", wait.as_secs_f64())));
        }
        tokio::time::sleep(wait).await;
        self.state.lock().unwrap().window.push_back(Instant::now());
        self.counters.restarts.fetch_add(1, Ordering::Relaxed);
        match self.connect_once().await {
            Ok((conn, raw, t)) => {
                let hash = schema_hash(&raw);
                if self.mounted_hash.get().is_some_and(|h| *h != hash) {
                    conn.shutdown.notify_one();
                    let why = "schema changed; restart the service".to_string();
                    tracing::error!(target: "plexus::child", child = %self.name, mounted = ?self.mounted_hash.get(), published = %hash, "the restarted child published another schema; not remounted: restart the service");
                    self.state.lock().unwrap().dead = Some(why.clone());
                    return Err(unavailable(&self.name, &why));
                }
                tracing::info!(target: "plexus::child", child = %self.name, spawn_ms = t.spawn_ms, schema_ms = t.schema_ms, "child restarted");
                self.state.lock().unwrap().conn = Some(Arc::clone(&conn));
                Ok(conn)
            }
            Err(why) => {
                let mut st = self.state.lock().unwrap();
                st.down_since = Some(Instant::now());
                st.why = why.clone();
                Err(unavailable(&self.name, &why))
            }
        }
    }

    fn live(&self) -> Result<Option<Arc<Conn>>, PlexusStreamItem> {
        let st = self.state.lock().unwrap();
        if let Some(why) = &st.dead {
            return Err(unavailable(&self.name, why));
        }
        Ok(st.conn.clone().filter(|c| c.alive()))
    }
}

/// The reader's end: every open call told, the supervisor told.
pub(super) fn gone(shared: &Weak<Shared>, conn: &Arc<Conn>, why: &str) {
    conn.on_gone(why);
    if let Some(s) = shared.upgrade() {
        s.lost(conn, why);
    }
}

/// One unary call: the first `data`'s content (the rest read to the end).
async fn ask(conn: &Conn, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
    let (_, mut rx) = conn.open(method, params, timeout).await.map_err(|e| match e {
        PlexusStreamItem::Error { message, .. } => message,
        other => format!("{other:?}"),
    })?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut first = None;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(PlexusStreamItem::Data { content, .. })) => {
                if first.is_none() {
                    first = Some(content.into_value());
                }
            }
            Ok(Some(PlexusStreamItem::Error { message, .. })) => return Err(message),
            Ok(Some(PlexusStreamItem::Done { .. })) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => return Err(format!("no answer in {timeout:?}")),
        }
    }
    first.ok_or_else(|| "it answered no data".to_string())
}
