//! NEST-15 · the service root is the primitive: a table of peers answered by
//! `peer(name)`.
//!
//! A service's top level is one table — each entry a peer by name — and
//! routing is `peer(name)` from the root down: `<name>.<method>` is the entry
//! `name`'s method, `<name>.<child>.<method>` its child's, and so on below it
//! (NEST-1, "The target", part 4). Every way onto the top level is an entry:
//!
//! ```text
//! .register(Tickets)        an entry, at build              (DynamicHub, unchanged)
//! --child menger=ws://…     a RemoteChild entry, at build   (`.register(child)`, unchanged)
//! root().insert(x)          an entry, while it serves       (an activation, a RemoteChild)
//! root().insert_peer(n, p)  any `Peer`, while it serves     (plexus-dyn's top-level peers)
//! root().remove(n)          gone, while it serves
//! ```
//!
//! The gate's index, `<service>.schema`, `.hash`, `.ir` and the schema's
//! `children` are read from the table: a change moves the service's hash,
//! drops what was described and indexed, and is said on
//! [`ServiceRoot::watch`] (and in the `plexus_hash` every item carries).
//!
//! The root's own methods (`call`, `hash`, `schema`, `ir`) are the root's:
//! the service's own name answers the root itself, never an entry.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::auth::AuthContext;
use super::peer::{Interface, Peer, PeerError, RouterPeer};
use super::plexus::{ActivationObject, ChildRouter, DynamicHub, PlexusError};
use super::schema::{PluginSchema, Schema};
use crate::types::Handle;
use super::PlexusStream;

/// One entry of the root's table: what the service calls (`object`) and
/// what routing walks below it (`router`).
#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) object: Arc<dyn ActivationObject>,
    pub(crate) router: Arc<dyn ChildRouter>,
}

/// The root's table, by name (ordered: every hash over the service is a
/// function of what it serves, PERF-21).
#[derive(Clone, Default)]
pub(crate) struct Table {
    pub(crate) entries: BTreeMap<String, Entry>,
    /// RETURNS-40: the entries' static children, counted — `ir`'s cheap bound.
    pub(crate) nested: usize,
}

/// Why the root would not take an entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootError {
    /// An entry is already served under `name` (use `replace`).
    #[error("a peer is already served as `{name}` at the top level")]
    Taken { name: String },
    /// `name` is the service's own: its methods would answer, never the entry
    /// (Z2H-8 / HOSTLESS-3).
    #[error("`{name}` is the service's own name: an entry under it would be unreachable")]
    Shadows { name: String },
    /// Not one segment of `[A-Za-z0-9_-]`.
    #[error("`{name}` is not a top-level name: one segment of letters, digits, `_` and `-`")]
    BadName { name: String },
    /// NEST-16: the entry is a graft whose needs this service does not
    /// serve as it was built against.
    #[error("{0}")]
    Needs(super::parent::NeedsMiss),
}

/// A top-level name: one segment.
pub(crate) fn check_name(name: &str) -> Result<(), RootError> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(RootError::BadName { name: name.to_string() });
    }
    Ok(())
}

/// The service root: its table of peers. A handle (cheap to clone) onto a
/// [`DynamicHub`] — [`DynamicHub::root`] — that reads and changes its top
/// level while it serves.
#[derive(Clone)]
pub struct ServiceRoot {
    pub(crate) hub: DynamicHub,
}

impl std::fmt::Debug for ServiceRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceRoot").field("service", &self.hub.runtime_namespace()).field("peers", &self.names()).finish()
    }
}

impl ServiceRoot {
    /// The primitive: the top-level peer `name`. The service's own name is
    /// not an entry (`NotFound`); call the service itself for its methods.
    pub async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        self.hub.table().entries.get(name).cloned().map(|e| Box::new(EntryPeer(e)) as Box<dyn Peer>).ok_or_else(|| PeerError::NotFound { name: name.to_string() })
    }

    /// Every top-level name, in order.
    pub fn names(&self) -> Vec<String> {
        self.hub.table().entries.keys().cloned().collect()
    }

    /// Whether `name` is served at the top level.
    pub fn contains(&self, name: &str) -> bool {
        self.hub.table().entries.contains_key(name)
    }

    /// Serve `activation` at the top level under its namespace, while the
    /// service serves; refused when the name is taken.
    pub fn insert<A: super::Activation + ChildRouter + Clone + 'static>(&self, activation: A) -> Result<(), RootError> {
        self.hub.insert_entry(activation.namespace().to_string(), DynamicHub::entry_of(activation), false).map(|_| ())
    }

    /// [`insert`](Self::insert), replacing whatever was served under the
    /// name; answers whether something was.
    pub fn replace<A: super::Activation + ChildRouter + Clone + 'static>(&self, activation: A) -> Result<bool, RootError> {
        self.hub.insert_entry(activation.namespace().to_string(), DynamicHub::entry_of(activation), true)
    }

    /// Serve any [`Peer`] at the top level as `name` (its schema's grants
    /// and roles requalified to `name`); `replace` takes the name over.
    /// Answers whether something was replaced.
    pub fn insert_peer(&self, name: impl Into<String>, peer: Arc<dyn Peer>, replace: bool) -> Result<bool, RootError> {
        let name = name.into();
        let entry = PeerObject::entry(name.clone(), peer);
        self.hub.insert_entry(name, entry, replace)
    }

    /// Stop serving `name` at the top level; answers whether it was served.
    pub fn remove(&self, name: &str) -> bool {
        self.hub.remove_entry(name)
    }

    /// The service's hash now (its schema's: what every item's `plexus_hash`
    /// says).
    pub fn hash(&self) -> String {
        self.hub.compute_hash()
    }

    /// Told every time the table changes: the service's hash after it.
    pub fn watch(&self) -> tokio::sync::watch::Receiver<String> {
        self.hub.watch_root()
    }
}

/// A top-level entry, as a peer.
struct EntryPeer(Entry);

#[async_trait]
impl Peer for EntryPeer {
    fn interface(&self) -> Interface {
        Interface::of(&self.0.object.plugin_schema())
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.0.object.call(method, params, auth, None).await
    }

    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match self.0.router.peer_child(name).await? {
            Some(router) => Ok(Box::new(RouterPeer::new(router))),
            None => Err(PeerError::NotFound { name: name.to_string() }),
        }
    }
}

/// A shared peer as a boxed one.
struct ArcPeer(Arc<dyn Peer>);

#[async_trait]
impl Peer for ArcPeer {
    fn interface(&self) -> Interface {
        self.0.interface()
    }
    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.0.call(method, params, auth).await
    }
    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        self.0.peer(name).await
    }
}

/// Any peer served at the top level: its schema is its interface's, under
/// the entry's name.
struct PeerObject {
    name: String,
    peer: Arc<dyn Peer>,
}

impl PeerObject {
    fn entry(name: String, peer: Arc<dyn Peer>) -> Entry {
        let router = Arc::new(super::peer::PeerRouter::new(Box::new(ArcPeer(peer.clone()))));
        Entry { object: Arc::new(PeerObject { name, peer }), router }
    }
}

/// `schema` as served under `name`: its roles' grants and its methods' own
/// grants requalified (`{ns}.m` → `<name>.m`), as a mount's are (NEST-4).
pub(crate) fn served_as(name: &str, mut schema: PluginSchema) -> PluginSchema {
    if schema.namespace == name {
        return schema;
    }
    let prefix = format!("{}.", schema.namespace);
    let requalify = |g: &String| match g.strip_prefix(&prefix) {
        Some(m) => format!("{name}.{m}"),
        None => g.clone(),
    };
    schema.roles = schema.roles.iter().map(|(r, gs)| (r.clone(), gs.iter().map(requalify).collect())).collect();
    for m in schema.methods.iter_mut() {
        if let Some(g) = m.grant.as_ref() {
            m.grant = Some(requalify(g));
        }
    }
    schema.namespace = name.to_string();
    schema
}

#[async_trait]
impl ActivationObject for PeerObject {
    fn namespace(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        ""
    }
    fn description(&self) -> &str {
        "a peer"
    }
    fn long_description(&self) -> Option<&str> {
        None
    }
    fn methods(&self) -> Vec<&str> {
        Vec::new()
    }
    fn method_help(&self, _method: &str) -> Option<String> {
        None
    }
    fn plugin_id(&self) -> uuid::Uuid {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, format!("peer:{}", self.name).as_bytes())
    }
    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>, _raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        let stream = self.peer.call(method, params, auth).await?;
        // Its own schema, as it is served here: under the entry's name.
        if method != "schema" {
            return Ok(stream);
        }
        use futures::StreamExt;
        let name = self.name.clone();
        Ok(Box::pin(stream.map(move |item| match item {
            super::types::PlexusStreamItem::Data { metadata, content_type, content } if content_type.ends_with(".schema") => {
                match content.decode::<super::schema::SchemaResult>() {
                    Ok(super::schema::SchemaResult::Plugin(schema)) => {
                        let served = super::schema::SchemaResult::Plugin(served_as(&name, schema));
                        let content = serde_json::to_value(&served).map(Into::into).unwrap_or(content);
                        super::types::PlexusStreamItem::Data { metadata, content_type: format!("{name}.schema").into(), content }
                    }
                    _ => super::types::PlexusStreamItem::Data { metadata, content_type, content },
                }
            }
            other => other,
        })))
    }
    async fn resolve_handle(&self, _handle: &Handle) -> Result<PlexusStream, PlexusError> {
        Err(PlexusError::HandleNotSupported(self.name.clone()))
    }
    fn plugin_schema(&self) -> PluginSchema {
        served_as(&self.name, self.peer.interface().schema().clone())
    }
    fn needs(&self) -> Option<Vec<super::schema::Need>> {
        self.peer.interface().schema().needs.clone()
    }
    fn static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        Vec::new()
    }
    fn schema(&self) -> Schema {
        let schema = self.plugin_schema();
        Schema::new(schema.namespace.clone(), schema.description.clone())
    }
}
