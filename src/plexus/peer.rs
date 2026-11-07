//! NEST-7 — **the primitive: an activation returns an activation.**
//!
//! A *peer* is an activation found by name, in this process or across the
//! network; the caller cannot tell which. An activation returns one from a
//! `#[plexus_macros::peer]` method:
//!
//! ```ignore
//! #[plexus_macros::peer(list = "integrations")]
//! async fn integration(&self, name: &str) -> Result<Box<dyn forge::ForgePeer>, PeerError>; // typed
//! #[plexus_macros::peer(list = "dendrites", search = "find")]
//! async fn dendrite(&self, name: &str) -> Result<Box<dyn Peer>, PeerError>;               // untyped
//! ```
//!
//! - [`Peer`] is the erased activation (`dyn Activation` cannot be written:
//!   `Activation` has an associated type). Every `Activation + ChildRouter`
//!   is one (the blanket impl below), `RemoteChild` included.
//! - [`Interface`] is a peer's shape, named and content-addressed: the IR of
//!   what it serves, its hash, and each method's own hash; two peers with one
//!   hash serve one shape, and [`Interface::satisfies`] is the shape check.
//! - [`PeerError`] is why a peer could not be returned, typed on the wire as
//!   an error item whose `error_kind` is the variant (`not_grafted`,
//!   `shape_mismatch`, …), never "method not found".
//! - A contract (a bodiless activation every method of which answers
//!   `Result<T, E>`) is a typed slot's interface: the macro emits
//!   `trait ForgePeer: Forge + Peer`, its [`Contract`] (the interface and the
//!   [`Stamp`] its client was generated from), and `ForgePeer` for the
//!   client over a [`PeerTransport`], which checks the backend's interface
//!   against the stamp — equal, go; it still [`satisfies`](Interface::satisfies)
//!   the stamp, say `drift` once and go; else [`PeerError::ShapeMismatch`] —
//!   and again whenever an item's `plexus_hash` moves.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use futures::StreamExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::auth::AuthContext;
use super::content_hash::{canonical_json, hash16};
use super::ir::ServiceIr;
use super::plexus::{Activation, ChildRouter, PlexusError};
use super::schema::{MethodRole, MethodSchema, PluginSchema};
use super::streaming::PlexusStream;
use super::types::{PlexusStreamItem, StreamMetadata};
use plexus_client::{DenyReason, OtherError, RemoteError};

// ===========================================================================
// PeerError
// ===========================================================================

/// Why a peer could not be returned — each failure typed, on the wire as an
/// error item whose `error_kind` is the variant's snake_case name, its fields
/// beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[serde(tag = "error_kind", rename_all = "snake_case")]
pub enum PeerError {
    /// No peer by this name.
    #[error("no peer named `{name}`")]
    NotFound { name: String },
    /// A graft point with nothing grafted under this name (GRAFT-1).
    #[error("nothing is grafted at `{at}` as `{name}` (it would serve `{interface}`)")]
    NotGrafted { at: String, name: String, interface: String },
    /// The peer is there but cannot be reached.
    #[error("the peer is unavailable: {reason}")]
    Unavailable { reason: String },
    /// The peer serves another shape: `wanted` and `got` are interface
    /// hashes, `methods` the methods missing or changed.
    #[error("the peer serves another shape (wanted {wanted}, got {got}): {}", methods.join(", "))]
    ShapeMismatch { wanted: String, got: String, methods: Vec<String> },
    /// The peer did not answer in time.
    #[error("the peer did not answer in time")]
    Timeout,
    /// The caller may not reach this peer.
    #[error("not allowed: {grant}")]
    Forbidden { grant: String },
}

impl PeerError {
    /// The wire's `error_kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            PeerError::NotFound { .. } => "not_found",
            PeerError::NotGrafted { .. } => "not_grafted",
            PeerError::Unavailable { .. } => "unavailable",
            PeerError::ShapeMismatch { .. } => "shape_mismatch",
            PeerError::Timeout => "timeout",
            PeerError::Forbidden { .. } => "forbidden",
        }
    }

    /// As the typed error an error item carries: a kind plexus-client does
    /// not know is [`RemoteError::Other`] with its fields; `forbidden` is the
    /// known refusal, naming the grant.
    pub fn to_remote(&self) -> RemoteError {
        match self {
            PeerError::Forbidden { grant } => RemoteError::Forbidden {
                reason: DenyReason::MissingGrant { grant: grant.clone(), scope: "*".into(), roles: vec![], held_on: vec![] },
            },
            other => {
                let mut fields = match serde_json::to_value(other) {
                    Ok(Value::Object(m)) => m,
                    _ => serde_json::Map::new(),
                };
                fields.remove("error_kind");
                RemoteError::Other(OtherError { kind: other.kind().into(), fields })
            }
        }
    }

    /// Back from the typed error an error item carries, when it is one.
    pub fn from_remote(e: &RemoteError) -> Option<PeerError> {
        match e {
            RemoteError::Forbidden { reason: DenyReason::MissingGrant { grant, .. } } => Some(PeerError::Forbidden { grant: grant.clone() }),
            RemoteError::Other(o) => {
                let mut m = o.fields.clone();
                m.insert("error_kind".into(), Value::String(o.kind.clone()));
                serde_json::from_value(Value::Object(m)).ok()
            }
            _ => None,
        }
    }

    /// From an error item, when it carries one.
    pub fn from_item(item: &PlexusStreamItem) -> Option<PeerError> {
        item.remote_error().and_then(PeerError::from_remote)
    }

    /// From a client's failure: a typed peer error the server sent, else the
    /// peer unavailable, saying why.
    pub fn from_client(e: &plexus_client::ClientError) -> PeerError {
        if let plexus_client::ClientError::Remote(r) = e {
            if let Some(p) = PeerError::from_remote(r) {
                return p;
            }
        }
        PeerError::Unavailable { reason: e.to_string() }
    }

    /// The error item a caller gets for it.
    pub fn item(&self, provenance: Vec<String>) -> PlexusStreamItem {
        let metadata = StreamMetadata::new(provenance, super::context::PlexusContext::hash());
        let mut item = PlexusStreamItem::error(metadata, self.to_remote(), matches!(self, PeerError::Unavailable { .. } | PeerError::Timeout));
        if let PlexusStreamItem::Error { message, .. } = &mut item {
            *message = self.to_string();
        }
        item
    }

    /// A stream of the one error item.
    pub fn stream(&self, provenance: Vec<String>) -> PlexusStream {
        let item = self.item(provenance);
        Box::pin(futures::stream::once(async move { item }))
    }
}

// ===========================================================================
// Interface
// ===========================================================================

/// A peer's shape, named and content-addressed: what `<ns>.ir` answers for
/// it, its hash, and each method's own hash. Two interfaces with one hash
/// serve one shape (descriptions, grants and the name aside).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Interface {
    /// The interface's name: a contract's namespace (`"forge"`), or the
    /// peer's own.
    pub name: String,
    /// The shape's hash: of every method's own hash, by name.
    pub hash: String,
    /// The IR of the shape (IR 3.0, as `<ns>.ir` writes it).
    pub ir: ServiceIr,
    /// Each method's own hash, by name ([`Interface::method_hash`]).
    #[serde(default)]
    pub methods: BTreeMap<String, String>,
    /// The schema the interface was read from: what a gate indexes for a
    /// typed slot (its methods' grants, targets and roles).
    pub schema: Box<PluginSchema>,
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.hash == other.hash
    }
}
impl Eq for Interface {}

/// Interfaces already built, by schema hash and name: an activation's
/// `interface()` is asked on every peer it becomes.
fn cache() -> &'static Mutex<HashMap<(String, String), Interface>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), Interface>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

impl Interface {
    /// The interface of `schema`, named after its namespace.
    pub fn of(schema: &PluginSchema) -> Self {
        Self::named(&schema.namespace, schema)
    }

    /// The interface of `schema`, named `name`.
    pub fn named(name: &str, schema: &PluginSchema) -> Self {
        let key = (name.to_string(), if schema.hash.is_empty() { canonical_json(&serde_json::to_value(schema).unwrap_or_default()) } else { schema.hash.clone() });
        if let Some(i) = cache().lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
            return i.clone();
        }
        let methods: BTreeMap<String, String> = schema
            .methods
            .iter()
            .filter(|m| !m.is_auto_schema() && matches!(m.role, MethodRole::Rpc))
            .map(|m| (m.name.clone(), Self::method_hash(m)))
            .collect();
        let hash = hash16(canonical_json(&serde_json::to_value(&methods).unwrap_or_default()).as_bytes());
        let mut schemas = BTreeMap::new();
        schemas.insert(Vec::<String>::new(), serde_json::to_value(schema).unwrap_or_default());
        let ir = super::ir::answer(name, &[vec![]], &schemas).unwrap_or_else(|_| null_ir());
        let i = Interface { name: name.to_string(), hash, ir, methods, schema: Box::new(schema.clone()) };
        cache().lock().unwrap_or_else(|p| p.into_inner()).insert(key, i.clone());
        i
    }

    /// The interface of a peer that describes nothing (a hand-written
    /// router): no methods, an empty hash.
    pub fn unknown(name: &str) -> Self {
        Interface {
            name: name.to_string(),
            hash: String::new(),
            ir: null_ir(),
            methods: BTreeMap::new(),
            schema: Box::new(PluginSchema::leaf(name, "", "", vec![])),
        }
    }

    /// A method's own hash: of its shape — its name, params, item, error,
    /// progress, cardinality, input and role — not its description, grant
    /// or hash, which say nothing of what crosses the wire.
    pub fn method_hash(m: &MethodSchema) -> String {
        let shape = serde_json::json!({
            "name": m.name,
            "params": m.params,
            "returns": m.returns,
            "error": m.error,
            "progress": m.progress,
            "cardinality": m.cardinality,
            "bidirectional": m.bidirectional,
            "request_type": m.request_type,
            "response_type": m.response_type,
            "input": m.input,
            "role": m.role,
        });
        hash16(canonical_json(&shape).as_bytes())
    }

    /// The schema the interface was read from.
    pub fn schema(&self) -> &PluginSchema {
        &self.schema
    }

    /// The methods `wanted` has that `self` lacks or serves under another
    /// hash, by name.
    pub fn moved_from(&self, wanted: &BTreeMap<String, String>) -> Vec<String> {
        wanted.iter().filter(|(name, hash)| self.methods.get(*name) != Some(*hash)).map(|(n, _)| n.clone()).collect()
    }

    /// GRAFT-1's shape check: does `self` serve at least `wanted`? Every
    /// method `wanted` has, under the same hash; `Err` names the methods
    /// missing or changed.
    pub fn satisfies(&self, wanted: &Interface) -> Result<(), PeerError> {
        if self.hash == wanted.hash {
            return Ok(());
        }
        let moved = self.moved_from(&wanted.methods);
        if moved.is_empty() {
            Ok(())
        } else {
            Err(PeerError::ShapeMismatch { wanted: wanted.hash.clone(), got: self.hash.clone(), methods: moved })
        }
    }
}

fn null_ir() -> ServiceIr {
    ServiceIr(Arc::from(serde_json::value::RawValue::from_string("null".into()).expect("null is JSON")))
}

// ===========================================================================
// Peer
// ===========================================================================

/// What a peer is: an activation, erased — `dyn Activation` cannot be
/// written (the associated `Methods` type), so this is the object-safe form.
/// Every `Activation + ChildRouter` is one.
#[async_trait]
pub trait Peer: Send + Sync {
    /// The shape this peer serves.
    fn interface(&self) -> Interface;
    /// Call one of its methods (`repos`, or a path below it: `child.m`).
    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError>;
    /// The primitive, one level down: this peer's own peers by name.
    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError>;
}

/// Every activation is a peer, local or remote: `RemoteChild` is an
/// `Activation + ChildRouter`, so it is one too.
#[async_trait]
impl<T: Activation + ChildRouter> Peer for T {
    fn interface(&self) -> Interface {
        Interface::of(&Activation::plugin_schema(self))
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError> {
        Activation::call(self, method, params, auth, None).await
    }

    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match ChildRouter::peer_child(self, name).await? {
            Some(router) => Ok(Box::new(RouterPeer::new(router))),
            None => Err(PeerError::NotFound { name: name.to_string() }),
        }
    }
}

/// A child router (what routing holds) as a peer.
pub struct RouterPeer {
    router: Box<dyn ChildRouter>,
}

impl RouterPeer {
    pub fn new(router: Box<dyn ChildRouter>) -> Self {
        Self { router }
    }
}

#[async_trait]
impl Peer for RouterPeer {
    fn interface(&self) -> Interface {
        match self.router.router_schema() {
            Some(s) => Interface::of(&s),
            None => Interface::unknown(self.router.router_namespace()),
        }
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.router.router_call(method, params, auth, None).await
    }

    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match self.router.peer_child(name).await? {
            Some(router) => Ok(Box::new(RouterPeer::new(router))),
            None => Err(PeerError::NotFound { name: name.to_string() }),
        }
    }
}

/// A peer as a child router: what a `#[peer]` slot hands routing. Calls go
/// to the peer's `call`; its own peers are its children.
pub struct PeerRouter {
    peer: Box<dyn Peer>,
    namespace: String,
}

impl PeerRouter {
    pub fn new(peer: Box<dyn Peer>) -> Self {
        let namespace = peer.interface().name;
        Self { peer, namespace }
    }
}

#[async_trait]
impl ChildRouter for PeerRouter {
    fn router_namespace(&self) -> &str {
        &self.namespace
    }

    async fn router_call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        _raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        self.peer.call(method, params, auth).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.peer.peer(name).await.ok().map(|p| Box::new(PeerRouter::new(p)) as Box<dyn ChildRouter>)
    }

    async fn peer_child(&self, name: &str) -> Result<Option<Box<dyn ChildRouter>>, PeerError> {
        let p = self.peer.peer(name).await?;
        Ok(Some(Box::new(PeerRouter::new(p))))
    }

    fn router_schema(&self) -> Option<PluginSchema> {
        let i = self.peer.interface();
        (!i.hash.is_empty()).then(|| i.schema().clone())
    }
}

/// How a `#[peer]` slot finds a peer by name: the slot's function, with
/// its activation.
pub type FindPeer = Arc<dyn Fn(String) -> futures::future::BoxFuture<'static, Result<Box<dyn Peer>, PeerError>> + Send + Sync>;

/// A `#[peer]` slot as routing holds it: reached as `<parent>.<slot>`, its
/// children are the peers the slot's function returns by name — a typed
/// slot's checked against its interface first (`ShapeMismatch` by interface
/// hash). `<parent>.<slot>.<name>.<method>` is a peer's method.
pub struct PeerSlot {
    namespace: String,
    interface: Option<Interface>,
    find: FindPeer,
    list: Option<ListPeers>,
}

/// How a `#[peer]` slot lists its names: its `list` sibling, collected.
pub type ListPeers = Arc<dyn Fn() -> futures::future::BoxFuture<'static, Vec<String>> + Send + Sync>;

impl PeerSlot {
    /// The slot `name` (`integration`), typed by `interface` (or not).
    pub fn new(name: impl Into<String>, interface: Option<Interface>, find: FindPeer) -> Self {
        Self { namespace: name.into(), interface, find, list: None }
    }

    /// The slot's names, listed (`#[peer(list = "…")]`): its schema lists
    /// each as a child, so a navigator steps to `<slot>.<name>`.
    pub fn with_list(mut self, list: ListPeers) -> Self {
        self.list = Some(list);
        self
    }

    /// The slot as a schema: one dynamic child (any name), typed by the
    /// slot's interface.
    pub fn schema(&self) -> PluginSchema {
        let entry = MethodSchema::new(self.namespace.clone(), "a peer, by name".to_string(), String::new())
            .with_role(MethodRole::DynamicChild {
                list_method: None,
                search_method: None,
                child: self.interface.as_ref().map(|i| Box::new(i.schema().clone())),
            })
            .with_content_hash();
        let mut s = PluginSchema::leaf(&self.namespace, "", "a peer slot", vec![entry]);
        s.hash = hash16(self.namespace.as_bytes());
        s
    }

    /// The peer named `name`, checked against the slot's interface.
    pub async fn get(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        let peer = (self.find)(name.to_string()).await?;
        if let Some(wanted) = &self.interface {
            peer.interface().satisfies(wanted)?;
        }
        Ok(peer)
    }
}

#[async_trait]
impl ChildRouter for PeerSlot {
    fn router_namespace(&self) -> &str {
        &self.namespace
    }

    async fn router_call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        // The slot's own schema: one dynamic child, any name — what a
        // navigator (synapse) reads to step from `host.integration` to
        // `host.integration.github`.
        if method == "schema" {
            let mut schema = self.schema();
            if let Some(list) = &self.list {
                let hash = self.interface.as_ref().map(|i| i.hash.clone());
                #[allow(deprecated)]
                {
                    schema.children = Some(
                        list()
                            .await
                            .into_iter()
                            .map(|name| super::schema::ChildSummary {
                                // Each name its own: a navigator keys its cache, and
                                // its cycle check, by this hash.
                                hash: hash16(format!("{}:{}.{name}", hash.clone().unwrap_or_default(), self.namespace).as_bytes()),
                                description: format!("the peer `{name}`"),
                                namespace: name,
                            })
                            .collect(),
                    );
                }
            }
            let content = serde_json::to_value(super::schema::SchemaResult::Plugin(schema)).unwrap_or_default();
            let metadata = StreamMetadata::new(vec![self.namespace.clone()], super::context::PlexusContext::hash());
            let items = vec![
                PlexusStreamItem::data(metadata.clone(), format!("{}.schema", self.namespace), content),
                PlexusStreamItem::done(metadata),
            ];
            return Ok(Box::pin(futures::stream::iter(items)));
        }
        super::plexus::route_to_child(self, method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.peer_child(name).await.ok().flatten()
    }

    async fn peer_child(&self, name: &str) -> Result<Option<Box<dyn ChildRouter>>, PeerError> {
        let peer = self.get(name).await?;
        Ok(Some(Box::new(PeerRouter::new(peer))))
    }

    fn router_schema(&self) -> Option<PluginSchema> {
        Some(self.schema())
    }
}

// ===========================================================================
// Contracts, stamps and the client's check
// ===========================================================================

/// A contract's shape, as a typed slot names it: implemented by the macro for
/// `dyn ForgePeer` (a contract's peer trait).
pub trait Contract {
    /// The contract's interface, at compile time's schema.
    fn interface() -> Interface;
    /// What its client was generated from.
    fn stamp() -> &'static Stamp;
}

/// What a generated client was built against: the interface's name, the
/// backend crate's version, the interface hash and each method's hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stamp {
    pub interface: String,
    pub version: String,
    pub hash: String,
    pub methods: Vec<(String, String)>,
}

impl Stamp {
    /// The stamp of `interface`, at `version`.
    pub fn of(version: &str, interface: &Interface) -> Self {
        Stamp {
            interface: interface.name.clone(),
            version: version.to_string(),
            hash: interface.hash.clone(),
            methods: interface.methods.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }
    }

    fn method_map(&self) -> BTreeMap<String, String> {
        self.methods.iter().cloned().collect()
    }
}

/// The backend's interface moved but still serves every method the stamp
/// has: said once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub from: String,
    pub to: String,
}

#[derive(Default)]
struct CheckState {
    /// The backend's interface, as last checked.
    interface: Option<Interface>,
    /// The stamp's methods it serves under another hash, or not at all.
    moved: Vec<String>,
    /// The last `plexus_hash` seen; a different one asks again.
    seen: Option<String>,
    /// Set when an item's `plexus_hash` moved since the last check.
    stale: bool,
    drift: Option<Drift>,
    drifts_said: usize,
    checks: usize,
}

/// A transport for a contract's client that checks the backend against the
/// client's [`Stamp`]: the backend's interface is asked once (and again when
/// an item's `plexus_hash` moves); every item is watched for that.
#[derive(Clone)]
pub struct PeerTransport<T> {
    inner: T,
    state: Arc<Mutex<CheckState>>,
}

impl<T> PeerTransport<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, state: Arc::default() }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// The backend's interface as last checked.
    pub fn interface(&self) -> Option<Interface> {
        self.lock().interface.clone()
    }

    /// The drift said, if the backend moved within the stamp.
    pub fn drift(&self) -> Option<Drift> {
        self.lock().drift.clone()
    }

    /// How many times the backend's interface was asked.
    pub fn checks(&self) -> usize {
        self.lock().checks
    }

    /// How many times drift was said (at most once per change).
    pub fn drifts_said(&self) -> usize {
        self.lock().drifts_said
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CheckState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn observe(&self, plexus_hash: &str) {
        if plexus_hash.is_empty() {
            return;
        }
        let mut s = self.lock();
        match &s.seen {
            Some(seen) if seen != plexus_hash => {
                s.stale = true;
                s.seen = Some(plexus_hash.to_string());
            }
            None => s.seen = Some(plexus_hash.to_string()),
            _ => {}
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<T: plexus_client::Transport + Clone + Send + Sync + 'static> PeerTransport<T> {
    /// Ask the backend's interface at `path` (its `schema`) and check it
    /// against `stamp`: equal → go; it serves every method of the stamp
    /// under the same hash → go, saying `drift` once; else the methods that
    /// moved are kept, and [`Self::admit`] refuses them all, a call only its
    /// own.
    pub async fn check(&self, path: &str, stamp: &Stamp) -> Result<(), PeerError> {
        let method = plexus_client::MethodRef::new(intern(&stamp.interface), "schema").at(path.to_string());
        let mut items = self.inner.call(method, serde_json::json!({}));
        let mut schema: Option<PluginSchema> = None;
        let mut plexus_hash = None;
        while let Some(item) = items.next().await {
            match item {
                Ok(plexus_client::StreamItem::Data { metadata, content, .. }) => {
                    plexus_hash = metadata.map(|m| m.plexus_hash);
                    schema = serde_json::from_value(content).ok();
                }
                Ok(plexus_client::StreamItem::Error { error, .. }) => {
                    return Err(PeerError::from_remote(&error).unwrap_or(PeerError::Unavailable { reason: error.to_string() }));
                }
                Ok(_) => {}
                Err(e) => return Err(PeerError::Unavailable { reason: e.to_string() }),
            }
        }
        drop(items);
        let schema = schema.ok_or_else(|| PeerError::Unavailable { reason: format!("`{path}.schema` answered no schema") })?;
        let got = Interface::named(&stamp.interface, &schema);
        let moved = if got.hash == stamp.hash { vec![] } else { got.moved_from(&stamp.method_map()) };
        let mut s = self.lock();
        s.checks += 1;
        s.stale = false;
        if let Some(h) = plexus_hash {
            s.seen = Some(h);
        }
        if got.hash != stamp.hash && moved.is_empty() {
            let drift = Drift { from: stamp.hash.clone(), to: got.hash.clone() };
            if s.drift.as_ref() != Some(&drift) {
                tracing::warn!(target: "plexus::peer", interface = %stamp.interface, from = %drift.from, to = %drift.to, "drift: the backend's interface moved within the stamp");
                s.drifts_said += 1;
                s.drift = Some(drift);
            }
        }
        s.moved = moved;
        s.interface = Some(got);
        Ok(())
    }

    /// Becoming a peer: check, and refuse a backend any of the stamp's
    /// methods moved on.
    pub async fn admit(&self, path: &str, stamp: &Stamp) -> Result<(), PeerError> {
        self.check(path, stamp).await?;
        let s = self.lock();
        if s.moved.is_empty() {
            Ok(())
        } else {
            Err(PeerError::ShapeMismatch {
                wanted: stamp.hash.clone(),
                got: s.interface.as_ref().map(|i| i.hash.clone()).unwrap_or_default(),
                methods: s.moved.clone(),
            })
        }
    }

    /// Before a call of `method`: check when never checked or when an item's
    /// `plexus_hash` moved; refuse the call when its own method moved.
    pub async fn guard(&self, path: &str, stamp: &Stamp, method: &str) -> Result<(), PeerError> {
        let ask = {
            let s = self.lock();
            s.interface.is_none() || s.stale
        };
        if ask {
            self.check(path, stamp).await?;
        }
        let s = self.lock();
        if s.moved.iter().any(|m| m == method) {
            return Err(PeerError::ShapeMismatch {
                wanted: stamp.hash.clone(),
                got: s.interface.as_ref().map(|i| i.hash.clone()).unwrap_or_default(),
                methods: vec![method.to_string()],
            });
        }
        Ok(())
    }

    /// After a call of `method`: when its items' `plexus_hash` moved, ask
    /// again once — and fail this call if its own method moved.
    pub async fn after(&self, path: &str, stamp: &Stamp, method: &str) -> Result<(), PeerError> {
        if self.lock().stale {
            self.guard(path, stamp, method).await?;
        }
        Ok(())
    }

    /// A peer's `call` through the client's transport: `method` (`repos`,
    /// or a path below the contract) at `path`, its items as the service's.
    /// Only a method the interface names is called (a name from a caller is
    /// never interned otherwise).
    pub async fn call_peer(&self, path: &str, method: &str, params: Value, known: &Interface) -> Result<PlexusStream, PlexusError> {
        let (prefix, name) = match method.rsplit_once('.') {
            Some((p, n)) => (Some(p), n),
            None => (None, method),
        };
        if prefix.is_some() || (name != "schema" && !known.methods.contains_key(name)) {
            return Err(PlexusError::MethodNotFound { activation: known.name.clone(), method: method.to_string() });
        }
        let name: &'static str = intern(name);
        let mref = plexus_client::MethodRef::new(intern(&known.name), name).at(path.to_string());
        let this = self.clone();
        let items = self.inner.call(mref, params).map(move |item| {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    let pe = PeerError::Unavailable { reason: e.to_string() };
                    return pe.item(vec![]);
                }
            };
            if let Some(m) = item_metadata(&item) {
                this.observe(&m);
            }
            let v = serde_json::to_value(&item).unwrap_or(Value::Null);
            serde_json::from_value::<PlexusStreamItem>(v).unwrap_or_else(|e| PeerError::Unavailable { reason: e.to_string() }.item(vec![]))
        });
        // Collected into an owned stream: the transport's borrows `self.inner`.
        let collected: Vec<PlexusStreamItem> = items.collect().await;
        Ok(Box::pin(futures::stream::iter(collected)))
    }
}

fn item_metadata(item: &plexus_client::StreamItem) -> Option<String> {
    match item {
        plexus_client::StreamItem::Data { metadata, .. }
        | plexus_client::StreamItem::Progress { metadata, .. }
        | plexus_client::StreamItem::Error { metadata, .. } => metadata.as_ref().map(|m| m.plexus_hash.clone()),
        _ => None,
    }
}

/// A method or interface name as `&'static str`, each distinct one leaked
/// once — only names an interface declares reach here.
fn intern(s: &str) -> &'static str {
    static NAMES: OnceLock<Mutex<std::collections::HashSet<&'static str>>> = OnceLock::new();
    let mut names = NAMES.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner());
    if let Some(n) = names.get(s) {
        return n;
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    names.insert(leaked);
    leaked
}

/// Every item a transport yields is watched for its `plexus_hash`.
#[cfg(not(target_arch = "wasm32"))]
impl<T: plexus_client::Transport + Send + Sync> plexus_client::Transport for PeerTransport<T> {
    fn call(&self, method: plexus_client::MethodRef, params: Value) -> plexus_client::ItemStream<'_> {
        Box::pin(self.inner.call(method, params).map(move |item| {
            if let Ok(i) = &item {
                if let Some(h) = item_metadata(i) {
                    self.observe(&h);
                }
            }
            item
        }))
    }

    fn call_raw(&self, method: plexus_client::MethodRef, params: Value) -> plexus_client::RawItemStream<'_> {
        Box::pin(self.call(method, params).map(|item| item.map(plexus_client::RawItem::from)))
    }
}
