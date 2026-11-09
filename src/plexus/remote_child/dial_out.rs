//! VISION-5 (LOCAL-5) · dial-out: a service with no listening port opens one
//! WebSocket to another service (a relay), signs in with its key on the
//! upgrade (spec/00), offers an activation on that socket (spec/14,
//! `{svc}.offer`) and serves it there — the far side of spec/12, the calls
//! coming in on the socket it opened. The same socket carries its own calls
//! out ([`Exposed::call`]): to the relay, and through it to every other
//! peer connected there.
//!
//! ```ignore
//! let exposed = Exposed::new(DialOut::new("wss://relay.example/ws", "~/.plexus/keys/alice.key").trust("key:<relay's>").mount("alice"));
//! exposed.serve(Greeter::new(exposed.clone()));   // reconnects, within its backoff, until stopped
//! exposed.mounted(Duration::from_secs(10)).await?; // `peers.alice` at the relay
//! let items = exposed.call("peers.bob.hello", json!({ "name": "alice" })).await;
//! ```
//!
//! | when | then |
//! | -- | -- |
//! | the socket opens | `_info` names the relay's `{svc}`; the offer goes as `{svc}.offer {namespace, activations, mount?}`; the relay asks the schema over the socket and answers the offer once mounted |
//! | no trusted key ([`DialOut::trust`]) | refused before dialing (KEEL-8) |
//! | the socket opens | the relay proves the trusted key at `_info {nonce}` (DYNAUTH-5's proof); none, or another: refused, nothing it sends served |
//! | the relay calls `{ns}.call {method, params, hop}` | served as a child serves (RETURNS-47's host) on a proven connection: each call in the hop's context, the hop believed only when it names the proven key |
//! | this side calls [`Exposed::call`] | `{svc}.call {method, params}` on the same socket: decided by the relay's gate as this key |
//! | the socket drops | every call either way ends; the state is `down`; it dials again within [`DialOut::backoff`] and offers again |
//! | the offer is refused | the state is `refused` naming why; it does not dial again until [`Exposed::serve`] is called again |

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue};
use tokio_tungstenite::tungstenite::Message;

use super::host::{serve_child_on, ChildPeer};
use super::link::{unavailable, Conn, Counters, SubKey};
use super::spec::{check_ws_url, is_insecure_ws, INSECURE_TRANSPORT};
use super::ws::{key_proof, principal_of, read_seed};
use super::Backoff;
use crate::plexus::plexus::Activation;
use crate::plexus::streaming::PlexusStream;
use crate::plexus::types::PlexusStreamItem;

/// Where a service dials out to, as whom, and under what name it asks to be
/// mounted.
#[derive(Debug, Clone)]
pub struct DialOut {
    /// The relay's socket: `ws://HOST:PORT/ws` (`wss://` with `child-wss`).
    pub url: String,
    /// The key file the upgrade's proof is signed with (spec/00): synapse's
    /// `~/.plexus/keys/<name>.key`, 0600. Read at each dial, never kept.
    pub key: PathBuf,
    /// The proof's agent id.
    pub agent: String,
    /// The mount name asked for (`peers.<mount>`); none: the activation's
    /// namespace.
    pub mount: Option<String>,
    /// The relay's key (`key:<64 hex>`), pinned (spec/14 rule 4). KEEL-8:
    /// required — none, and the dial-out is refused before dialing. At each
    /// connect the relay proves it at `_info` (the nonce signed, as a
    /// mount's child proves its key, DYNAUTH-5); a relay that proves none,
    /// or another, is refused and nothing it sends is served. A hop is
    /// believed only when it names this key as the service acting.
    pub trust: Option<String>,
    /// Dialing again after the socket drops.
    pub backoff: Backoff,
    /// `_info`, the offer's answer, and each of this side's calls' opens.
    pub timeout: Duration,
    /// KEEL-7: dial plain `ws://` beyond loopback (`transport.insecure_ws`,
    /// a test network's). Off: such a relay is refused before a socket opens
    /// ([`check_ws_url`]); on: dialed, and [`DialState::Mounted`] says
    /// `insecure`.
    pub insecure_ws: bool,
    /// KEEL-8 (DYNAUTH-8): a PEM file of certificate authorities a `wss://`
    /// relay's certificate may chain to, beside the webpki roots — as a
    /// mount's [`ChildOptions::tls_roots`](super::ChildOptions::tls_roots).
    pub tls_roots: Option<PathBuf>,
}

impl DialOut {
    /// Dial `url`, signed in with the key in `key`.
    pub fn new(url: impl Into<String>, key: impl Into<PathBuf>) -> Self {
        Self {
            url: url.into(),
            key: key.into(),
            agent: "plexus-service".into(),
            mount: None,
            trust: None,
            backoff: Backoff { initial: Duration::from_millis(250), max: Duration::from_secs(10), per_minute: usize::MAX },
            timeout: Duration::from_secs(10),
            insecure_ws: false,
            tls_roots: None,
        }
    }

    /// Ask to be mounted as `name`.
    pub fn mount(mut self, name: impl Into<String>) -> Self {
        self.mount = Some(name.into());
        self
    }

    /// The relay's key (`key:<64 hex>`): it must prove it at each connect,
    /// and hops are believed only from it (pinned).
    pub fn trust(mut self, principal: impl Into<String>) -> Self {
        self.trust = Some(principal.into());
        self
    }

    /// The proof's agent id.
    pub fn agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = agent.into();
        self
    }

    /// KEEL-7: allow plain `ws://` beyond loopback ([`DialOut::insecure_ws`]).
    pub fn insecure_ws(mut self, on: bool) -> Self {
        self.insecure_ws = on;
        self
    }

    /// KEEL-8: a PEM file of CAs a `wss://` relay may chain to
    /// ([`DialOut::tls_roots`]).
    pub fn tls_roots(mut self, roots: impl Into<PathBuf>) -> Self {
        self.tls_roots = Some(roots.into());
        self
    }

    /// KEEL-7: [`DialOut::insecure_ws`] as `transport.insecure_ws` in `c`
    /// says, when it says more than its default; KEEL-8: and
    /// [`DialOut::tls_roots`] as `transport.tls_roots` says.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn configured(mut self, c: &crate::plexus::config::Config) -> Self {
        use crate::plexus::config::{settings::{TRANSPORT_INSECURE_WS, TRANSPORT_TLS_ROOTS}, Source};
        if c.source(&TRANSPORT_INSECURE_WS) != Source::Default {
            self.insecure_ws = c.get(&TRANSPORT_INSECURE_WS);
        }
        if c.source(&TRANSPORT_TLS_ROOTS) != Source::Default {
            self.tls_roots = c.get(&TRANSPORT_TLS_ROOTS).map(Into::into);
        }
        self
    }
}

/// Where a dialed-out service stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DialState {
    /// Not yet dialed, or dialing.
    Connecting,
    /// Mounted at the relay as `path` (`peers.<mount>`). `insecure`
    /// (KEEL-7): over plain `ws://` beyond loopback, as
    /// [`DialOut::insecure_ws`] allowed.
    Mounted {
        mount: String,
        path: String,
        service: String,
        relay: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        insecure: bool,
    },
    /// The socket dropped or could not open; dialing again.
    Down { why: String },
    /// The relay refused the offer; not dialing again.
    Refused { why: String },
    /// [`Exposed::stop`]ped.
    Stopped,
}

struct Live {
    conn: Arc<Conn>,
    service: String,
}

struct ExposedInner {
    opts: DialOut,
    live: Mutex<Option<Live>>,
    state: watch::Sender<DialState>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
    counters: Arc<Counters>,
}

impl Drop for ExposedInner {
    fn drop(&mut self) {
        if let Some(t) = self.task.lock().unwrap().take() {
            t.abort();
        }
    }
}

/// A service's one outbound socket to a relay: what it serves there, and
/// the calls it makes over it. Cheap to clone; [`Self::serve`] holds a weak
/// reference, so the socket goes with the last clone (or [`Self::stop`]).
#[derive(Clone)]
pub struct Exposed {
    inner: Arc<ExposedInner>,
}

impl std::fmt::Debug for Exposed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exposed").field("url", &self.inner.opts.url).field("state", &self.state()).finish()
    }
}

impl Exposed {
    /// Not dialed until [`Self::serve`]: an activation that calls out through
    /// the relay holds a clone of this before it is served.
    pub fn new(opts: DialOut) -> Self {
        Self {
            inner: Arc::new(ExposedInner {
                opts,
                live: Mutex::new(None),
                state: watch::channel(DialState::Connecting).0,
                task: Mutex::new(None),
                counters: Arc::new(Counters::default()),
            }),
        }
    }

    /// The options it dials with.
    pub fn options(&self) -> &DialOut {
        &self.inner.opts
    }

    /// The principal this side signs in as (its key's), or why the key does
    /// not read.
    pub fn principal(&self) -> Result<String, String> {
        read_seed(&self.inner.opts.key).map(|k| principal_of(&k))
    }

    /// Where it stands now.
    pub fn state(&self) -> DialState {
        self.inner.state.borrow().clone()
    }

    /// Its state, watched.
    pub fn watch(&self) -> watch::Receiver<DialState> {
        self.inner.state.subscribe()
    }

    /// Wait until mounted (its `path` at the relay), or refused, or `timeout`.
    pub async fn mounted(&self, timeout: Duration) -> Result<String, String> {
        let mut rx = self.watch();
        let settled = tokio::time::timeout(timeout, async {
            rx.wait_for(|s| matches!(s, DialState::Mounted { .. } | DialState::Refused { .. } | DialState::Stopped)).await.map(|s| s.clone())
        })
        .await;
        match settled {
            Ok(Ok(DialState::Mounted { path, .. })) => Ok(path),
            Ok(Ok(other)) => Err(format!("{other:?}")),
            Ok(Err(_)) => Err("stopped".into()),
            Err(_) => Err(format!("not mounted in {timeout:?} ({:?})", self.state())),
        }
    }

    /// Dial, offer `activation`, serve it; dial again whenever the socket
    /// drops. Replaces a previous `serve`.
    pub fn serve<A: Activation + Clone>(&self, activation: A) {
        let weak = Arc::downgrade(&self.inner);
        let task = tokio::spawn(async move {
            let mut failures = 0usize;
            loop {
                let Some(inner) = weak.upgrade() else { return };
                inner.state.send_replace(DialState::Connecting);
                let outcome = session(&inner, activation.clone()).await;
                inner.live.lock().unwrap().take();
                let backoff = inner.opts.backoff;
                match outcome {
                    Outcome::Refused(why) => {
                        tracing::warn!(target: "plexus::dial", url = %inner.opts.url, "the offer was refused: {why}");
                        inner.state.send_replace(DialState::Refused { why });
                        return;
                    }
                    Outcome::Dropped { why, was_mounted } => {
                        tracing::warn!(target: "plexus::dial", url = %inner.opts.url, "{why}; dialing again");
                        inner.state.send_replace(DialState::Down { why });
                        failures = if was_mounted { 0 } else { failures + 1 };
                    }
                }
                drop(inner);
                tokio::time::sleep(backoff.delay(failures)).await;
            }
        });
        if let Some(old) = self.inner.task.lock().unwrap().replace(task.abort_handle()) {
            old.abort();
        }
    }

    /// Close the socket and stop dialing.
    pub fn stop(&self) {
        if let Some(t) = self.inner.task.lock().unwrap().take() {
            t.abort();
        }
        if let Some(live) = self.inner.live.lock().unwrap().take() {
            live.conn.shutdown.notify_one();
        }
        self.inner.state.send_replace(DialState::Stopped);
    }

    /// Call `method` (a path at the relay: `peers.bob.hello`, `peers.list`)
    /// over this side's socket, as this side's key: `{svc}.call`, decided by
    /// the relay's gate. Not connected: one `child_unavailable` item.
    pub async fn call(&self, method: &str, params: Value) -> PlexusStream {
        let one = |item: PlexusStreamItem| -> PlexusStream { Box::pin(futures::stream::iter([item])) };
        let live = self.inner.live.lock().unwrap().as_ref().map(|l| (Arc::clone(&l.conn), l.service.clone()));
        let Some((conn, service)) = live else {
            return one(unavailable("relay", &format!("not connected to {} ({:?})", self.inner.opts.url, self.state())));
        };
        match conn.open(&format!("{service}.call"), json!({ "method": method, "params": params }), self.inner.opts.timeout).await {
            Ok((sid, rx)) => Box::pin(Items { rx, sid, conn, over: false }),
            Err(item) => one(item),
        }
    }
}

/// A call's items, until its terminal one; dropped before it, unsubscribed.
struct Items {
    rx: mpsc::Receiver<PlexusStreamItem>,
    sid: SubKey,
    conn: Arc<Conn>,
    over: bool,
}

impl futures::Stream for Items {
    type Item = PlexusStreamItem;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<PlexusStreamItem>> {
        if self.over {
            return std::task::Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(item)) => {
                self.over = matches!(item, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. });
                std::task::Poll::Ready(Some(item))
            }
            std::task::Poll::Ready(None) => {
                self.over = true;
                std::task::Poll::Ready(Some(unavailable("relay", "the connection closed")))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl Drop for Items {
    fn drop(&mut self) {
        if !self.over {
            self.conn.unsubscribe(&self.sid);
        }
    }
}

enum Outcome {
    Refused(String),
    Dropped { why: String, was_mounted: bool },
}

fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    n[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    n
}

/// The offer's request id: a string, so it can never be one of the client
/// `Conn`'s numbered requests (spec/14 rule 2: ids are per direction).
const OFFER_ID: &str = "offer";

/// One socket, from dial to drop.
async fn session<A: Activation + Clone>(inner: &Arc<ExposedInner>, activation: A) -> Outcome {
    let opts = &inner.opts;
    let dropped = |why: String| Outcome::Dropped { why, was_mounted: false };
    // KEEL-7: the transport decided before any socket opens or the key is
    // read — `ws://` beyond loopback only under `transport.insecure_ws`.
    if let Err(why) = check_ws_url(&opts.url, opts.insecure_ws) {
        return Outcome::Refused(format!("{INSECURE_TRANSPORT}: {why}"));
    }
    // KEEL-8: a relay is named by its key before it is dialed; the socket is
    // never a pipe, so nothing on it is believed without that key's proof.
    let trusted = match trusted_key(opts.trust.as_deref()) {
        Ok(k) => k,
        Err(why) => return Outcome::Refused(why),
    };
    if opts.url.starts_with("wss://") && !cfg!(feature = "child-wss") {
        return Outcome::Refused("a wss:// relay needs plexus-core's `child-wss` feature (TLS)".into());
    }
    let mut req = match opts.url.as_str().into_client_request() {
        Ok(r) => r,
        Err(e) => return Outcome::Refused(format!("`{}`: {e}", opts.url)),
    };
    let key = match read_seed(&opts.key) {
        Ok(k) => k,
        Err(e) => return Outcome::Refused(e),
    };
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let proof = key_proof(&key, opts.url.trim_end_matches('/'), &opts.agent, &nonce(), ts);
    drop(key);
    match HeaderValue::from_str(&format!("Bearer {proof}")) {
        Ok(v) => req.headers_mut().insert(AUTHORIZATION, v),
        Err(e) => return Outcome::Refused(e.to_string()),
    };
    // KEEL-8: the TLS a mount's dial is made with (`tls_roots` honoured),
    // and its one timeout on the upgrade (a socket accepted and left).
    #[cfg(feature = "child-wss")]
    let connecting = {
        let tls = match opts.url.starts_with("wss://") {
            true => match super::ws::tls_config(opts.tls_roots.as_deref()) {
                Ok(c) => Some(tokio_tungstenite::Connector::Rustls(c)),
                Err(why) => return Outcome::Refused(why),
            },
            false => None,
        };
        // spec/14: a client that serves must not delay small writes (Nagle).
        tokio_tungstenite::connect_async_tls_with_config(req, None, true, tls)
    };
    #[cfg(not(feature = "child-wss"))]
    let connecting = tokio_tungstenite::connect_async_with_config(req, None, true);
    let socket = match tokio::time::timeout(opts.timeout, connecting).await {
        Err(_) => return dropped(format!("dialing {}: no answer to the upgrade in {:?}", opts.url, opts.timeout)),
        Ok(Ok((s, _))) => s,
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => return dropped(format!("the upgrade to {} was refused: HTTP {}", opts.url, resp.status())),
        Ok(Err(e)) => return dropped(format!("dialing {}: {e}", opts.url)),
    };
    let (mut sink, mut stream) = socket.split();

    // This side's calls out: a client `Conn` on the socket's outbound queue.
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn = Conn::new("relay", None, out.clone(), 64, Arc::clone(&inner.counters));
    // The calls in: RETURNS-47's host, on a pipe of lines this side feeds —
    // started only once the relay has proved the trusted key (KEEL-8).
    let (mut host_in, host_r) = tokio::io::duplex(1 << 16);
    let (host_w, host_out) = tokio::io::duplex(1 << 16);
    let proven = Arc::new(AtomicBool::new(false));
    let mut host: Option<tokio::task::JoinHandle<std::io::Result<()>>> = None;

    // Writer: the client's frames and the host's lines, in the order made.
    let out_host = out.clone();
    let host_lines = tokio::spawn(async move {
        let mut lines = BufReader::new(host_out).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if out_host.send(l.into_bytes()).is_err() {
                break;
            }
        }
    });
    let shutdown = Arc::clone(&conn);
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                first = out_rx.recv() => {
                    let Some(first) = first else { break };
                    let mut ok = sink.feed(Message::text(String::from_utf8_lossy(&first).into_owned())).await.is_ok();
                    while let (true, Ok(more)) = (ok, out_rx.try_recv()) {
                        ok = sink.feed(Message::text(String::from_utf8_lossy(&more).into_owned())).await.is_ok();
                    }
                    if !ok || sink.flush().await.is_err() {
                        break;
                    }
                }
                _ = shutdown.shutdown.notified() => {
                    let _ = sink.close().await;
                    break;
                }
            }
        }
    });

    // Reader: by the frame's shape (spec/14 rule 2) — a call into this side
    // to the host; the offer's answer to its waiter; the rest to the client.
    let (offer_tx, offer_rx) = oneshot::channel::<Value>();
    let reader_conn = Arc::clone(&conn);
    let (reader_proven, refuse_out) = (Arc::clone(&proven), out.clone());
    let reader = tokio::spawn(async move {
        let mut offer_tx = Some(offer_tx);
        let why = loop {
            let text = match stream.next().await {
                Some(Ok(Message::Text(t))) => t.as_bytes().to_vec(),
                Some(Ok(Message::Binary(b))) => b.to_vec(),
                Some(Ok(Message::Close(f))) => break format!("the relay closed the socket ({})", f.map(|f| f.code.to_string()).unwrap_or_else(|| "no code".into())),
                Some(Ok(_)) => continue,
                Some(Err(e)) => break format!("the socket: {e}"),
                None => break "the relay closed the socket".to_string(),
            };
            let shape: Value = match serde_json::from_slice(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let (method, id) = (shape.get("method"), shape.get("id"));
            if method.is_some() && id.is_some() {
                // KEEL-8: a call before the relay proved its key is answered
                // refused, never served.
                if !reader_proven.load(Ordering::Acquire) {
                    let refusal = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": "the relay has not proved its key", "data": { "error_kind": "forbidden" } } });
                    let _ = refuse_out.send(serde_json::to_vec(&refusal).unwrap_or_default());
                    continue;
                }
                let mut line = text;
                line.push(b'\n');
                if host_in.write_all(&line).await.is_err() {
                    break "the host stopped".to_string();
                }
            } else if method.is_none() && id.and_then(Value::as_str) == Some(OFFER_ID) {
                if let Some(tx) = offer_tx.take() {
                    let _ = tx.send(shape);
                }
            } else {
                reader_conn.on_message(&text).await;
            }
        };
        reader_conn.on_gone(&why);
        reader_conn.shutdown.notify_one();
        why
    });

    let ended = |host: Option<tokio::task::JoinHandle<std::io::Result<()>>>, why: String, was_mounted: bool| {
        if let Some(h) = host {
            h.abort();
        }
        host_lines.abort();
        writer.abort();
        Outcome::Dropped { why, was_mounted }
    };

    // The relay's namespace and its key, proved: its `_info` over a nonce
    // (DYNAUTH-5's proof, the one a mount asks of its child).
    let asked = crate::plexus::peer_token::random_nonce();
    let info = async {
        let (_, mut rx) = conn.open("_info", json!({ "nonce": asked }), opts.timeout).await.map_err(|e| format!("{e:?}"))?;
        while let Some(item) = rx.recv().await {
            if let PlexusStreamItem::Data { content, .. } = item {
                let content = content.into_value();
                if let Some(b) = content.get("backend").and_then(Value::as_str) {
                    let field = |k: &str| content.get(k).and_then(Value::as_str).map(str::to_string);
                    return Ok((b.to_string(), field("key"), field("proof")));
                }
            }
        }
        Err::<_, String>("its `_info` names no backend".into())
    };
    let (service, key, key_proof) = match tokio::time::timeout(opts.timeout, info).await {
        Ok(Ok(s)) => s,
        Ok(Err(why)) => {
            reader.abort();
            return ended(host, format!("asking the relay's `_info`: {why}"), false);
        }
        Err(_) => {
            reader.abort();
            return ended(host, format!("the relay did not answer `_info` in {:?}", opts.timeout), false);
        }
    };
    if let Err(why) = relay_proved(&trusted, &service, &asked, key.as_deref(), key_proof.as_deref()) {
        reader.abort();
        ended(host, String::new(), false);
        tracing::warn!(target: "plexus::audit", url = %opts.url, "dial-out refused: {why}");
        return Outcome::Refused(why);
    }
    let _ = conn.ns.set(service.clone());
    let _ = conn.peer_key.set(trusted.clone());
    host = Some(tokio::spawn(serve_child_on(activation.clone(), host_r, host_w, ChildPeer::connection(trusted.clone(), [trusted.clone()]))));
    proven.store(true, Ordering::Release);

    // The offer (spec/14), answered once the relay has mounted this side.
    let ns = activation.namespace().to_string();
    let schema_hash = activation.plugin_schema().hash;
    let mut params = json!({ "namespace": ns, "activations": [ns], "schema_hash": schema_hash, "schema": null });
    if let Some(m) = &opts.mount {
        params["mount"] = json!(m);
    }
    let _ = out.send(serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": OFFER_ID, "method": format!("{service}.offer"), "params": params })).unwrap_or_default());
    let answer = match tokio::time::timeout(opts.timeout * 2, offer_rx).await {
        Ok(Ok(a)) => a,
        Ok(Err(_)) => {
            let why = reader.await.unwrap_or_else(|_| "the socket".into());
            return ended(host, format!("before the offer was answered: {why}"), false);
        }
        Err(_) => {
            reader.abort();
            return ended(host, format!("the offer was not answered in {:?}", opts.timeout * 2), false);
        }
    };
    if let Some(e) = answer.get("error") {
        reader.abort();
        ended(host, String::new(), false);
        let kind = e.pointer("/data/error_kind").and_then(Value::as_str).unwrap_or("refused");
        let message = e.get("message").and_then(Value::as_str).unwrap_or("");
        return Outcome::Refused(format!("{kind}: {message}"));
    }
    let result = answer.get("result").cloned().unwrap_or(Value::Null);
    let mount = result.get("mount").and_then(Value::as_str).unwrap_or(&ns).to_string();
    let path = result.get("path").and_then(Value::as_str).unwrap_or(&mount).to_string();
    let relay = result.pointer("/service/principal").and_then(Value::as_str).unwrap_or("").to_string();
    // KEEL-8: the relay acts as the key it proved, or not at all — another
    // principal named here is refused, as a remount proving another key is.
    if relay != trusted {
        reader.abort();
        ended(host, String::new(), false);
        let why = format!("the relay proved {trusted} but names {} as the service acting: refused, as another key is", if relay.is_empty() { "no principal" } else { &relay });
        tracing::warn!(target: "plexus::audit", url = %opts.url, "dial-out refused: {why}");
        return Outcome::Refused(why);
    }
    *inner.live.lock().unwrap() = Some(Live { conn: Arc::clone(&conn), service: service.clone() });
    let insecure = is_insecure_ws(&opts.url);
    if insecure {
        tracing::warn!(target: "plexus::dial", url = %opts.url, "insecure: dialed out over plain ws:// beyond loopback (transport.insecure_ws); the key proof and every hop cross in clear");
    }
    tracing::info!(target: "plexus::dial", url = %opts.url, %path, %relay, insecure, "mounted at the relay");
    inner.state.send_replace(DialState::Mounted { mount, path, service, relay, insecure });

    let why = reader.await.unwrap_or_else(|_| "the socket".into());
    ended(host, why, true)
}

/// KEEL-8: the relay's key a dial-out trusts — `key:<64 hex>` — or why the
/// dial-out may not dial.
fn trusted_key(trust: Option<&str>) -> Result<String, String> {
    let Some(t) = trust else {
        return Err("no trusted key: a dial-out names its relay by key (`DialOut::trust`, `key:<64 hex>`), which the relay proves at each connect; without one nothing it sends could be believed".into());
    };
    match crate::plexus::peer_token::key_of(t) {
        Some(_) => Ok(t.to_string()),
        None => Err(format!("the trusted relay `{t}` is not a key (`key:<64 hex>`): a relay is named by the key it proves")),
    }
}

/// KEEL-8: whether the relay's `_info` proved `trusted` over `nonce`.
fn relay_proved(trusted: &str, backend: &str, nonce: &str, key: Option<&str>, proof: Option<&str>) -> Result<(), String> {
    let Some(key) = key else {
        return Err(format!("the relay proved no key at `_info` (trusted: {trusted})"));
    };
    if key != trusted {
        return Err(format!("the relay proved another key ({key}) than the one trusted ({trusted})"));
    }
    crate::plexus::peer_token::check_key_proof(key, proof.unwrap_or_default(), nonce, backend)
        .map(|_| ())
        .map_err(|e| format!("the relay's `_info` names the key {key} without proving it: {e}"))
}

/// The principal a key file's proof proves (`key:<64 hex>`), or why the key
/// does not read — a service naming itself, as a relay does in its hops.
pub fn key_principal(path: &std::path::Path) -> Result<String, String> {
    read_seed(path).map(|k| principal_of(&k))
}
