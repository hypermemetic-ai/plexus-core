//! VISION-5 (LOCAL-5) · dial-in peers: a service that dialed in, offered a
//! surface on its own socket (plexus-wire spec/14, `{svc}.offer`), and is
//! mounted here under a name for as long as that socket lives.
//!
//! [`Peers`] is an activation (its namespace `peers` by default) whose
//! children are the peers connected now: `peers.<name>.<method>` reaches
//! the peer `<name>`, `peers.list` names every one, `peers.watch` follows
//! them coming and going. Each peer is a [`RemoteChild`] whose connection
//! is the socket the peer opened — the calls into it are spec/12's, sent
//! the other way along that socket (spec/14 rule 1), with the hop naming
//! the service acting (`principal`) and the caller it acts for (`for`).
//!
//! The transport stays outside: plexus-core has no WebSocket server, so a
//! transport hands each accepted socket to [`Peers::socket`] and feeds it
//! (plexus-transport: a `ConnectionHook` calling [`PeerSocket::on_frame`]
//! and [`PeerSocket::on_close`], and a task writing what
//! [`PeerSocket`]'s receiver yields through the connection's writer).
//!
//! | when | then |
//! | -- | -- |
//! | a socket sends `{svc}.offer {namespace, mount?}` | its principal must hold `peers.offer` on the mount name (the gate, when one is given); its schema is asked over the socket; it is mounted as `peers.<mount>` and the offer is answered `{offered, mount, path, schema_hash, service}` |
//! | an anonymous socket offers | refused `unauthenticated`; nothing is mounted |
//! | the name is held by another principal's socket | refused `name_taken` |
//! | the same principal offers the name from a new socket | the new socket takes it over (a reconnect) |
//! | a caller calls `peers.<mount>.<m>` | the service's gate decides `peers.<mount>.<m>` first; the call crosses with the hop, the peer decides again (spec/12) |
//! | the socket closes | the mount goes, now: `peers.<mount>` is not found, a call open on it ends `child_unavailable` |

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use plexus_auth_core::grants::{Gate, Grant, GrantSet, Refusal, RoleTable, Roles};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};

use super::link::{gone, meta, Conn, Kept, Shared};
use super::{mount_schema, node_schema, Backoff, ChildOptions, ChildSpec, Inner, MountTimings, RemoteChild};
use crate::plexus::auth::AuthContext;
use crate::plexus::method_enum::MethodEnumSchema;
use crate::plexus::plexus::{route_to_child, Activation, ChildRouter, PlexusError};
use crate::plexus::schema::{Cardinality, MethodRole, MethodSchema, PluginSchema};
use crate::plexus::streaming::PlexusStream;
use crate::plexus::types::PlexusStreamItem;

/// One peer, as `peers.list` names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerInfo {
    /// The mount name: the peer is `peers.<name>`.
    pub name: String,
    /// The principal its socket proved at the upgrade (spec/00).
    pub principal: String,
    /// The namespace it offered (its own `{ns}`).
    pub namespace: String,
    /// Its methods, as its schema lists them.
    pub methods: Vec<String>,
    /// Seconds since it was mounted.
    pub connected_secs: u64,
}

/// What `peers.watch` says: a peer came or went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PeerEvent {
    /// Mounted (or, on a watch's start, mounted already).
    Mounted { name: String, principal: String, namespace: String, methods: Vec<String> },
    /// Its socket closed, or a new socket of the same principal took the name.
    Unmounted { name: String, why: String },
}

/// [`Peers`]' own methods are named, not a Rust enum of the macro's.
#[derive(Debug, Clone, Copy)]
pub enum PeersMethods {}

impl JsonSchema for PeersMethods {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PeersMethods".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "description": "list, watch, offer — and every peer connected, by its mount name" })
    }
}

impl MethodEnumSchema for PeersMethods {
    fn method_names() -> &'static [&'static str] {
        &["list", "watch", "offer"]
    }

    fn schema_with_consts() -> Value {
        serde_json::to_value(schemars::schema_for!(PeersMethods)).unwrap_or(Value::Null)
    }
}

/// A mounted peer.
struct Entry {
    child: RemoteChild,
    principal: String,
    namespace: String,
    socket: u64,
    since: Instant,
}

impl Entry {
    fn info(&self, name: &str) -> PeerInfo {
        PeerInfo {
            name: name.to_string(),
            principal: self.principal.clone(),
            namespace: self.namespace.clone(),
            methods: self.child.inner.schema.methods.iter().map(|m| m.name.clone()).collect(),
            connected_secs: self.since.elapsed().as_secs(),
        }
    }
}

struct PeersInner {
    ns: String,
    service: String,
    principal: String,
    gate: RwLock<Option<Arc<Gate>>>,
    opts: ChildOptions,
    table: RwLock<BTreeMap<String, Entry>>,
    events: broadcast::Sender<PeerEvent>,
    next_socket: AtomicU64,
    on_change: RwLock<Vec<Box<dyn Fn() + Send + Sync>>>,
}

/// The peers connected now, as an activation: `peers.list`, `peers.watch`,
/// and `peers.<name>.<method>` into each. Cheap to clone.
#[derive(Clone)]
pub struct Peers {
    inner: Arc<PeersInner>,
}

impl std::fmt::Debug for Peers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peers").field("ns", &self.inner.ns).field("names", &self.names()).finish()
    }
}

/// A name a peer may be mounted under: one segment, not one of
/// [`Peers`]' own methods.
fn valid_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("a mount name is 1–64 characters".into());
    }
    if let Some(bad) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-')) {
        return Err(format!("the mount name `{name}` holds `{bad}`: only letters, digits, `_` and `-`"));
    }
    if matches!(name, "list" | "watch" | "offer" | "schema") {
        return Err(format!("`{name}` is one of the peers' own methods"));
    }
    Ok(())
}

impl Peers {
    /// Peers mounted under `ns` (`peers`) of the service `service` (whose
    /// `{service}.offer` a socket sends), calling into each as `principal`
    /// (the hop's acting service: its key's principal, or `service:<ns>`).
    pub fn new(ns: impl Into<String>, service: impl Into<String>, principal: impl Into<String>) -> Self {
        let service = service.into();
        let opts = ChildOptions {
            // A dial-in peer is never redialed: it comes back by dialing again.
            backoff: Backoff { initial: Duration::ZERO, max: Duration::ZERO, per_minute: 0 },
            ..ChildOptions::for_service(&service)
        };
        Self {
            inner: Arc::new(PeersInner {
                ns: ns.into(),
                service,
                principal: principal.into(),
                gate: RwLock::new(None),
                opts,
                table: RwLock::new(BTreeMap::new()),
                events: broadcast::channel(256).0,
                next_socket: AtomicU64::new(1),
                on_change: RwLock::new(Vec::new()),
            }),
        }
    }

    /// The gate that decides offers (`<ns>.offer` on the mount name). Calls
    /// into a peer are decided by the service's own gate, as every call.
    /// Without one every signed-in socket may offer.
    pub fn with_gate(self, gate: Arc<Gate>) -> Self {
        *self.inner.gate.write().unwrap() = Some(gate);
        self
    }

    /// [`Self::with_gate`] on a `Peers` already registered (the gate is made
    /// from the service's roles, which need the activation first).
    pub fn set_gate(&self, gate: Arc<Gate>) {
        *self.inner.gate.write().unwrap() = Some(gate);
    }

    /// Each call into a peer opens within this, and the peer's schema is
    /// answered within it at the offer. Default 10 s.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        let mut s = self;
        if let Some(inner) = Arc::get_mut(&mut s.inner) {
            inner.opts.timeout = timeout;
        }
        s
    }

    /// Call `f` whenever a peer is mounted or goes — the service's
    /// [`DynamicHub::schema_moved`](crate::DynamicHub::schema_moved), so the
    /// next `schema` it answers lists the peers as they stand.
    pub fn on_change(&self, f: impl Fn() + Send + Sync + 'static) {
        self.inner.on_change.write().unwrap().push(Box::new(f));
    }

    /// A peer came or went: the gate's grants moved (the roles grow and
    /// shrink with the peers) and what the service describes moved.
    fn moved(&self) {
        if let Some(g) = self.inner.gate.read().unwrap().as_ref() {
            g.generation().bump();
        }
        for f in self.inner.on_change.read().unwrap().iter() {
            f();
        }
    }

    /// The names mounted now.
    pub fn names(&self) -> Vec<String> {
        self.inner.table.read().unwrap().keys().cloned().collect()
    }

    /// Every peer mounted now.
    pub fn list(&self) -> Vec<PeerInfo> {
        self.inner.table.read().unwrap().iter().map(|(n, e)| e.info(n)).collect()
    }

    /// The peer mounted as `name`, if one is.
    pub fn get(&self, name: &str) -> Option<RemoteChild> {
        self.inner.table.read().unwrap().get(name).map(|e| e.child.clone())
    }

    /// Peers coming and going, from now.
    pub fn events(&self) -> broadcast::Receiver<PeerEvent> {
        self.inner.events.subscribe()
    }

    /// Roles over `base` that also hold what the peers connected now
    /// declare (each peer's `roles`, under `<ns>.<name>.<method>`), and —
    /// when `every` names a role — every method of every peer for it, with
    /// `<ns>.list`, `<ns>.watch` and `<ns>.offer`. Answered from memory, as
    /// the table stands at each check.
    /// A `base` that is a [`RoleStore`](crate::plexus::RoleStore) (an
    /// admin's `auth.role_set`) makes the result one too.
    pub fn roles<R: Roles>(&self, base: R, every: Option<&str>) -> PeerRoles<R> {
        PeerRoles { base, peers: self.clone(), every: every.map(str::to_string) }
    }

    /// A socket the transport accepted, signed in as `auth` (or anonymous).
    /// Feed it every inbound frame ([`PeerSocket::on_frame`]) and its close
    /// ([`PeerSocket::on_close`]); write every frame the receiver yields on
    /// the socket, in order.
    pub fn socket(&self, auth: Option<AuthContext>) -> (Arc<PeerSocket>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (out, rx) = mpsc::unbounded_channel();
        let (inbound, mut in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let socket = Arc::new(PeerSocket {
            peers: self.clone(),
            id: self.inner.next_socket.fetch_add(1, Ordering::Relaxed),
            principal: auth.as_ref().and_then(|a| a.principal()).map(|p| p.to_string()),
            auth,
            out,
            inbound,
            link: Mutex::new(None),
            mount: Mutex::new(None),
        });
        // The answers and items of this side's calls, routed in arrival
        // order (spec/14 rule 7), never on the transport's reader.
        let weak = Arc::downgrade(&socket);
        tokio::spawn(async move {
            while let Some(frame) = in_rx.recv().await {
                let link = weak.upgrade().and_then(|s| s.link.lock().unwrap().clone());
                if let Some((conn, _)) = link {
                    conn.on_message(&frame).await;
                }
            }
        });
        (socket, rx)
    }

    fn unmount(&self, name: &str, socket: u64, why: &str) {
        let removed = {
            let mut t = self.inner.table.write().unwrap();
            match t.get(name) {
                Some(e) if e.socket == socket => t.remove(name),
                _ => None,
            }
        };
        if removed.is_some() {
            tracing::info!(target: "plexus::peers", peer = %name, "peer unmounted: {why}");
            self.moved();
            let _ = self.inner.events.send(PeerEvent::Unmounted { name: name.to_string(), why: why.to_string() });
        }
    }

    fn data(&self, method: &str, content: Value) -> PlexusStreamItem {
        let ns = &self.inner.ns;
        PlexusStreamItem::Data { metadata: meta(ns).into(), content_type: format!("{ns}.{method}").into(), content: content.into() }
    }

    fn done(&self) -> PlexusStreamItem {
        PlexusStreamItem::Done { metadata: meta(&self.inner.ns) }
    }

    fn own_methods(&self) -> Vec<MethodSchema> {
        let ns = &self.inner.ns;
        vec![
            MethodSchema::new("list", "The peers connected now: each one's mount name, principal, namespace and methods", "")
                .with_cardinality(Cardinality::Many)
                .with_returns(schemars::schema_for!(PeerInfo))
                .with_grant(format!("{ns}.list"))
                .with_content_hash(),
            MethodSchema::new("watch", "Peers as they come and go: those mounted now, then each mount and unmount", "")
                .with_cardinality(Cardinality::Many)
                .with_returns(schemars::schema_for!(PeerEvent))
                .with_grant(format!("{ns}.watch"))
                .with_content_hash(),
            MethodSchema::new("offer", "Offered on a peer's own socket (`{service}.offer`, spec/14), not called: its grant decides who may be mounted, on the mount name", "")
                .with_cardinality(Cardinality::One)
                .with_grant(format!("{ns}.offer"))
                .with_content_hash(),
        ]
    }
}

/// [`Peers::roles`]: a role table that grows with the peers connected.
pub struct PeerRoles<R = RoleTable> {
    base: R,
    peers: Peers,
    every: Option<String>,
}

#[async_trait]
impl<R: crate::plexus::RoleStore> crate::plexus::RoleStore for PeerRoles<R> {
    async fn set(&self, role: &plexus_auth_core::audit::RoleName, grants: GrantSet) -> Result<(), crate::plexus::StoreError> {
        self.base.set(role, grants).await
    }
}

impl<R: Roles> Roles for PeerRoles<R> {
    fn grants(&self, role: &plexus_auth_core::audit::RoleName) -> Option<GrantSet> {
        let base = self.base.grants(role);
        if matches!(base, Some(GrantSet::All)) {
            return base;
        }
        let mut set = match base {
            Some(GrantSet::Listed(s)) => s,
            _ => Default::default(),
        };
        let every = self.every.as_deref() == Some(role.as_str());
        let ns = &self.peers.inner.ns;
        if every {
            for m in ["list", "watch", "offer"] {
                set.insert(Grant::new(format!("{ns}.{m}")));
            }
        }
        let mut known = every || self.base.grants(role).is_some();
        for (name, e) in self.peers.inner.table.read().unwrap().iter() {
            let schema = &e.child.inner.schema;
            if every {
                set.extend(schema.methods.iter().map(|m| Grant::new(format!("{ns}.{name}.{}", m.name))));
            }
            // A peer's own roles are already `<ns>.<name>.<method>` (the mount
            // requalified them under its path).
            if let Some(gs) = schema.roles.get(role.as_str()) {
                known = true;
                set.extend(gs.iter().map(Grant::new));
            }
            // Its entry in `<ns>.schema` (a child's), seen by whoever may
            // call something in it.
            if every || schema.roles.get(role.as_str()).is_some_and(|g| !g.is_empty()) {
                set.insert(Grant::new(format!("{ns}.{name}")));
            }
        }
        known.then_some(GrantSet::Listed(set))
    }

    fn names(&self) -> Vec<plexus_auth_core::audit::RoleName> {
        let mut names = self.base.names();
        if let Some(e) = &self.every {
            names.push(plexus_auth_core::audit::RoleName::new(e));
        }
        names
    }
}

/// One accepted socket, as [`Peers`] sees it: the offer it may make, the
/// answers and items of the calls made into it, its close.
pub struct PeerSocket {
    peers: Peers,
    id: u64,
    auth: Option<AuthContext>,
    principal: Option<String>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
    /// Once offered: the connection the calls into the peer ride.
    link: Mutex<Option<(Arc<Conn>, Arc<Shared>)>>,
    /// The name it is mounted under.
    mount: Mutex<Option<String>>,
}

/// The parts of a frame its shape is read by (spec/14 rule 2).
#[derive(Deserialize)]
struct Shape {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
}

/// A refusal of an offer: spec/05's error with a typed `data.error_kind`.
fn refusal(id: &Value, code: i64, kind: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message, "data": { "error_kind": kind } } })).unwrap_or_default()
}

impl PeerSocket {
    /// The principal the socket proved, if any.
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    /// The name it is mounted under, once its offer was taken.
    pub fn mount(&self) -> Option<String> {
        self.mount.lock().unwrap().clone()
    }

    /// One inbound frame, before the method table sees it. `true`: taken —
    /// the offer, or an answer or item of a call this side opened into the
    /// peer; anything else is the transport's (a call into the service).
    pub fn on_frame(self: &Arc<Self>, frame: &[u8]) -> bool {
        let Ok(shape) = serde_json::from_slice::<Shape>(frame) else { return false };
        match (&shape.method, &shape.id) {
            (Some(m), Some(id)) if *m == format!("{}.offer", self.peers.inner.service) => {
                let (me, id, params) = (Arc::clone(self), id.clone(), shape.params.unwrap_or(Value::Null));
                tokio::spawn(async move {
                    let answer = me.offer(&id, params).await;
                    let _ = me.out.send(answer);
                });
                true
            }
            // A response: to a request of this side's (rule 2) — when it has
            // made any.
            (None, Some(_)) => self.link.lock().unwrap().is_some() && self.inbound.send(frame.to_vec()).is_ok(),
            // An item of a call this side opened (`params.result`).
            (Some(_), None) => {
                let item = shape.params.as_ref().is_some_and(|p| p.get("subscription").is_some() && p.get("result").is_some());
                item && self.link.lock().unwrap().is_some() && self.inbound.send(frame.to_vec()).is_ok()
            }
            _ => false,
        }
    }

    /// The socket is gone: every call into the peer ends
    /// `child_unavailable`, and its mount goes.
    pub fn on_close(&self) {
        let why = "its connection closed";
        if let Some((conn, shared)) = self.link.lock().unwrap().take() {
            gone(&Arc::downgrade(&shared), &conn, why);
        }
        if let Some(name) = self.mount.lock().unwrap().take() {
            self.peers.unmount(&name, self.id, why);
        }
    }

    async fn offer(self: &Arc<Self>, id: &Value, params: Value) -> Vec<u8> {
        let peers = &self.peers;
        let Some(namespace) = params.get("namespace").and_then(Value::as_str).map(str::to_string) else {
            return refusal(id, -32602, "invalid_params", "an offer names its `namespace`");
        };
        let name = params.get("mount").and_then(Value::as_str).unwrap_or(&namespace).to_string();
        if let Err(why) = valid_name(&name).and_then(|_| valid_name(&namespace).map_err(|w| format!("its namespace: {w}"))) {
            return refusal(id, -32602, "invalid_params", &why);
        }
        let Some(principal) = self.principal.clone() else {
            return refusal(id, -32001, "unauthenticated", "sign in first: an anonymous socket offers nothing");
        };
        let gate = peers.inner.gate.read().unwrap().clone();
        if let Some(gate) = gate {
            let grant = Grant::new(format!("{}.offer", peers.inner.ns));
            if let Err(r) = gate.check(self.auth.as_ref(), &grant, Some(&name)) {
                let (code, kind, message) = match r {
                    Refusal::Unauthenticated | Refusal::Ended { .. } => (-32001, "unauthenticated", r.to_string()),
                    Refusal::MissingGrant { .. } => (-32003, "forbidden", format!("{principal} holds no `{grant}` on `{name}`")),
                };
                return refusal(id, code, kind, &message);
            }
        }
        if self.link.lock().unwrap().is_some() {
            return refusal(id, -32602, "invalid_params", "this socket has offered already");
        }
        if let Some(e) = peers.inner.table.read().unwrap().get(&name) {
            if e.principal != principal {
                return refusal(id, -32010, "name_taken", &format!("`{name}` is held by another principal's connection"));
            }
        }
        // The calls into the peer ride this socket, from now (its schema first).
        let path = format!("{}.{name}", peers.inner.ns);
        let spec = ChildSpec::Ws { name: path.clone(), url: format!("dial-in:{principal}") };
        let shared = Shared::new(spec, peers.inner.opts.clone(), peers.inner.principal.clone());
        let conn = Conn::new(&path, None, self.out.clone(), peers.inner.opts.buffer, Arc::clone(&shared.counters));
        let _ = conn.ns.set(namespace.clone());
        shared.install(Arc::clone(&conn));
        *self.link.lock().unwrap() = Some((Arc::clone(&conn), Arc::clone(&shared)));
        let t0 = Instant::now();
        let hop = json!({ "principal": peers.inner.principal, "for": [], "limit": null, "call": uuid::Uuid::new_v4().to_string() });
        let asked = ask(&conn, &format!("{namespace}.call"), json!({ "method": format!("{namespace}.schema"), "params": {}, "hop": hop }), peers.inner.opts.timeout).await;
        // NEST-4 (vision merge): a dial-in peer's static tree is walked and
        // kept as a dialed child's is, within the same one timeout.
        let mounted = match asked {
            Ok(raw) => {
                let deadline = t0 + peers.inner.opts.timeout;
                shared.walk(&conn, &namespace, &raw, deadline).await.map(|nodes| Kept { top: raw, nodes })
            }
            Err(e) => Err(e),
        };
        let mounted = mounted.and_then(|kept| {
            let hash = kept.hash();
            let schema = mount_schema(&path, kept.top)?;
            let nodes = kept.nodes.into_iter().map(|(p, raw)| node_schema(&p, raw).map(|s| (p, s))).collect::<Result<Vec<_>, _>>()?;
            let _ = shared.mounted_hash.set(hash.clone());
            Ok((schema, nodes, hash))
        });
        let (schema, nodes, hash) = match mounted {
            Ok(m) => m,
            Err(why) => {
                self.link.lock().unwrap().take();
                return refusal(id, -32000, "invalid_params", &format!("not mounted: {why}"));
            }
        };
        let timings = MountTimings { spawn_ms: 0.0, schema_ms: t0.elapsed().as_secs_f64() * 1e3, merge_ms: 0.0 };
        let methods: Vec<String> = schema.methods.iter().map(|m| m.name.clone()).collect();
        let child = RemoteChild { inner: Arc::new(Inner::new(shared, schema, nodes, timings)) };
        // NEST-16: its calls back are held to what it needs.
        child.inner.shared.upcalls.set_needs(child.inner.needs.as_deref());
        let replaced = peers.inner.table.write().unwrap().insert(name.clone(), Entry { child, principal: principal.clone(), namespace: namespace.clone(), socket: self.id, since: Instant::now() });
        *self.mount.lock().unwrap() = Some(name.clone());
        if replaced.is_some() {
            let _ = peers.inner.events.send(PeerEvent::Unmounted { name: name.clone(), why: "a new connection of the same principal took the name".into() });
        }
        tracing::info!(target: "plexus::peers", peer = %name, %principal, %namespace, methods = methods.len(), "peer mounted");
        peers.moved();
        let _ = peers.inner.events.send(PeerEvent::Mounted { name: name.clone(), principal, namespace: namespace.clone(), methods });
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": {
            "offered": namespace,
            "mount": name,
            "path": path,
            "schema_hash": params.get("schema_hash").cloned().unwrap_or(Value::String(hash)),
            "service": { "namespace": peers.inner.service, "principal": peers.inner.principal },
        } }))
        .unwrap_or_default()
    }
}

/// One unary call into the peer: the first `data`'s content.
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
                first.get_or_insert(content.into_value());
            }
            Ok(Some(PlexusStreamItem::Error { message, .. })) => return Err(message),
            Ok(Some(PlexusStreamItem::Done { .. })) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => return Err(format!("no answer in {timeout:?}")),
        }
    }
    first.ok_or_else(|| "it answered no data".to_string())
}

#[async_trait]
impl Activation for Peers {
    type Methods = PeersMethods;

    fn namespace(&self) -> &str {
        &self.inner.ns
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> &str {
        "The peers connected now: services that dialed in and offered a surface, each mounted by name while its socket lives"
    }

    fn methods(&self) -> Vec<&str> {
        vec!["list", "watch", "offer"]
    }

    fn method_help(&self, method: &str) -> Option<String> {
        self.own_methods().into_iter().find(|m| m.name == method).map(|m| m.description)
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>, raw: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        match method {
            "schema" => {
                let schema = self.plugin_schema();
                let content = match params.get("method").and_then(Value::as_str) {
                    Some(m) => match schema.methods.iter().find(|x| x.name == m) {
                        Some(ms) => serde_json::to_value(ms).unwrap_or_default(),
                        None => return Err(PlexusError::MethodNotFound { activation: self.inner.ns.clone(), method: m.to_string() }),
                    },
                    None => serde_json::to_value(&schema).unwrap_or_default(),
                };
                let ns = &self.inner.ns;
                let item = PlexusStreamItem::Data { metadata: meta(ns).into(), content_type: format!("{ns}.schema").into(), content: content.into() };
                Ok(Box::pin(futures::stream::iter([item, self.done()])))
            }
            "list" => {
                let items: Vec<PlexusStreamItem> = self.list().into_iter().map(|p| self.data("list", serde_json::to_value(p).unwrap_or_default())).chain([self.done()]).collect();
                Ok(Box::pin(futures::stream::iter(items)))
            }
            "watch" => {
                let mut rx = self.events();
                let now: Vec<PeerEvent> = self
                    .list()
                    .into_iter()
                    .map(|p| PeerEvent::Mounted { name: p.name, principal: p.principal, namespace: p.namespace, methods: p.methods })
                    .collect();
                let me = self.clone();
                Ok(Box::pin(async_stream::stream! {
                    for e in now {
                        yield me.data("watch", serde_json::to_value(e).unwrap_or_default());
                    }
                    loop {
                        match rx.recv().await {
                            Ok(e) => yield me.data("watch", serde_json::to_value(e).unwrap_or_default()),
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    yield me.done();
                }))
            }
            "offer" => Err(PlexusError::ExecutionError(format!(
                "an offer is made on the peer's own socket, as `{}.offer` (spec/14), not called",
                self.inner.service
            ))),
            m if m.contains('.') => route_to_child(self, m, params, auth, raw).await,
            m if self.get(m).is_some() => Err(PlexusError::MethodNotFound { activation: format!("{}.{m}", self.inner.ns), method: String::new() }),
            m => Err(PlexusError::MethodNotFound { activation: self.inner.ns.clone(), method: m.to_string() }),
        }
    }

    /// Nothing of its own on the socket: reached through `{service}.call`,
    /// behind the service's gate.
    fn into_rpc_methods(self) -> jsonrpsee::Methods {
        jsonrpsee::Methods::new()
    }

    /// Its own methods, and each peer connected now as a child (a method of
    /// role `static_child` named for it), as the table stands.
    fn plugin_schema(&self) -> PluginSchema {
        let mut methods = self.own_methods();
        let mut children = Vec::new();
        for (name, e) in self.inner.table.read().unwrap().iter() {
            let s = &e.child.inner.schema;
            let description = format!("a peer: {} ({}, connected as {})", s.description, e.namespace, e.principal);
            methods.push(MethodSchema::new(name.clone(), description.clone(), s.hash.clone()).with_role(MethodRole::StaticChild));
            // IR-4's side-table, still what a client navigates by (synapse).
            children.push(crate::plexus::schema::ChildSummary { namespace: name.clone(), description, hash: s.hash.clone() });
        }
        let mut schema = PluginSchema::leaf(self.inner.ns.clone(), self.version(), self.description(), methods);
        #[allow(deprecated)]
        if !children.is_empty() {
            schema.children = Some(children);
        }
        let ns = &self.inner.ns;
        schema.roles.insert("viewer".into(), vec![format!("{ns}.list"), format!("{ns}.watch")]);
        schema
    }
}

#[async_trait]
impl ChildRouter for Peers {
    fn router_namespace(&self) -> &str {
        &self.inner.ns
    }

    async fn router_call(&self, method: &str, params: Value, auth: Option<&AuthContext>, raw: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        Activation::call(self, method, params, auth, raw).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.get(name).map(|c| Box::new(c) as Box<dyn ChildRouter>)
    }

    async fn list_children(&self) -> Option<BoxStream<'_, String>> {
        Some(futures::stream::iter(self.names()).boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_name_is_one_segment_and_not_a_method() {
        assert!(valid_name("alice").is_ok());
        assert!(valid_name("a-b_9").is_ok());
        assert!(valid_name("a.b").is_err());
        assert!(valid_name("").is_err());
        assert!(valid_name("list").is_err());
    }
}
