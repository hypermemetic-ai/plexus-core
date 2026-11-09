//! POLYGLOT-5 — the child seam opened: an activation in another process,
//! mounted under a name.
//!
//! [`RemoteChild`] is the second implementation of [`ChildRouter`] (and
//! [`Activation`]): its other end is a process on stdio or a service on a
//! WebSocket speaking plexus-wire (spec 01–05, 07, 11 and 12, *the hop
//! between services*). A [`DynamicHub`](super::DynamicHub) registers it like
//! any activation — its schema and roles merged under the mount name, its
//! methods granted, refused and listed as an in-process activation's.
//!
//! ```ignore
//! let echo = RemoteChild::connect("echo=stdio:python3 -I stub_child.py".parse()?, ChildOptions::for_service("menger")).await?;
//! let service = DynamicHub::new("menger").register(tickets).register(echo);
//! ```
//!
//! # What crosses
//!
//! The gate decides first; a refused call never reaches the child. An
//! admitted one is `{ns}.call {method, params, hop}` with
//! `hop = {principal, for, limit {grant, held_on} | null, call}`: the
//! service acting, the caller it acts for, the gate's verdict as a ceiling
//! and a call id — built from the verified principal and
//! [`current_reach`](super::grant_gate::current_reach) only (an error outside
//! a call, RETURNS-47: then nothing crosses), never from the caller's
//! credential. Items come back unchanged, in order; the child's
//! terminal item ends the caller's stream. A caller that lets go sends
//! `{ns}.call_unsub`. A child gone is one `child_unavailable` error — the
//! end (spec/03: an error is terminal) — and the next call starts it again,
//! within its [`Backoff`]. An item nobody asked for is dropped, logged and
//! counted ([`ChildStats::unasked`]).
//!
//! # A child's children (NEST-4) and its dynamic children (NEST-6)
//!
//! The mount walks the child's static tree once and keeps it: every level's
//! schema is answered from it and nothing crosses (spec/12 rule 7). A
//! dynamic child's slot (`#[child] fn planet(&self, name)`, or a
//! `#[peer]` slot) stays on its parent's kept schema with its type, so the
//! host's gate decides `<mount>.solar.earth.info` on the slot grant
//! `<mount>.solar.{planet}.info` (an untyped slot whole, on
//! `<mount>.solar.{planet}`) and the mount forwards it as `{ns}.call
//! {method: "{ns}.solar.earth.info", hop}`, `hop.limit.grant` the slot grant
//! in the child's terms; the child checks the slot ([`serve_child_on`]) and
//! answers an unknown name with its own not-found. A slot's list and search
//! methods are ordinary methods, forwarded. The one schema that crosses is
//! an instance's (`<mount>.solar.earth.schema`): once per name, kept under
//! the name and the `plexus_hash` it came with — at most
//! `--child-schema-cache` names, the least recently used out
//! ([`ChildStats::name_schemas`], [`ChildStats::name_schema_hits`]); an item
//! through the name with another `plexus_hash` drops it, and a restart drops
//! every name.

//! # A child calls its service back (NEST-11)
//!
//! While a call is open into the child, the child may call the service back
//! on the same connection — `_host.call {method, params, under}`, `under`
//! the forwarded call's `hop.call` (plexus-wire spec/14). The service routes
//! it through its own routing and gate as that call's caller, within that
//! call's reach, and ends it when that call ends; outside a live call it
//! answers a schema only (`upcall.rs`). The far side in Rust calls back
//! through [`host()`], a `Transport` a generated client takes.

// RETURNS-47: the far side in Rust — an activation served as a child, each
// call in its hop's context.
mod host;
mod link;
// NEST-6: one dynamic instance's schema, kept per name.
mod names;
// RETURNS-36: a peer on plexus-wire's spec as main wrote it, read as 0.8.
mod peer;
mod spec;
// NEST-11: a child calls its service back, under a call it serves.
mod upcall;
#[cfg(feature = "child-ws")]
mod ws;
#[cfg(feature = "clap")]
mod args;
// VISION-5 (LOCAL-5): dial-in peers (the accepting side) and dial-out (the
// side with no listening port).
mod dial_in;
#[cfg(feature = "child-ws")]
mod dial_out;

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use async_trait::async_trait;
use futures::Stream;
use plexus_auth_core::grants::{GrantsGeneration, Reach};
use serde_json::{json, Value};
use tokio::sync::mpsc;

pub use host::{host, serve_child, serve_child_on, serve_child_stdio, serve_child_with, ChildPeer, HostTransport, ServeChild};
pub use upcall::{Consented, HOST_CALL, HOST_CALL_UNSUB};
pub use link::MountTimings;
pub use spec::{parse_duration, Backoff, ChildError, ChildOptions, ChildSpec};
#[cfg(feature = "clap")]
pub use args::ChildArgs;
pub use dial_in::{PeerEvent, PeerInfo, PeerRoles, PeerSocket, Peers, PeersMethods};
#[cfg(feature = "child-ws")]
pub use dial_out::{key_principal, DialOut, DialState, Exposed};

use link::{meta, too_many, unavailable, Conn, Counters, Shared, SubKey};

use super::auth::AuthContext;
use super::method_enum::MethodEnumSchema;
use super::plexus::{Activation, ChildRouter, PlexusError};
use super::schema::{MethodRole, PluginSchema};
use super::streaming::PlexusStream;
use super::types::PlexusStreamItem;

/// DYNAUTH-8 (TM-3): who a child proved it was at its mount — what a
/// restart is held to. Its `_info`'s `backend`, and on `wss://` the key its
/// certificate holds (sha256 of the SubjectPublicKeyInfo, hex): a renewed
/// certificate over the same key is the same peer; a new key is not. A
/// peer's own Ed25519 key, proved at `_info` over a nonce, joins it
/// (DYNAUTH-5): a restart proving another key is refused as one proving
/// another certificate key is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerIdentity {
    /// The backend its `_info` names.
    pub backend: String,
    /// On `wss://`: sha256 of its certificate's public key, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// DYNAUTH-5: the Ed25519 key it proved at `_info` (`key:<hex>`), if it
    /// proved one — what a peer token is addressed and bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl PeerIdentity {
    fn of(conn: &Conn) -> Self {
        Self { backend: conn.ns().to_string(), tls_key: conn.tls_key.get().cloned(), key: conn.peer_key.get().cloned() }
    }
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend `{}`", self.backend)?;
        match &self.tls_key {
            Some(k) => write!(f, ", TLS key {}", &k[..k.len().min(16)]),
            None => write!(f, ", no TLS key"),
        }?;
        match &self.key {
            Some(k) => write!(f, ", key {}", &k[..k.len().min(20)]),
            None => Ok(()),
        }
    }
}

/// What the seam has seen of one child.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChildStats {
    /// Calls open now.
    pub open: usize,
    /// Items the child sent for a call it was not given (dropped).
    pub unasked: u64,
    /// Times the child was started (or dialed) again after it went.
    pub restarts: u64,
    /// Calls forwarded, in all.
    pub calls: u64,
    /// NEST-6: a dynamic instance's schema asked across the hop
    /// (`<mount>.<path>.<name>.schema`, once per name while it is kept).
    pub name_schemas: u64,
    /// NEST-6: a dynamic instance's schema answered from what the mount kept.
    pub name_schema_hits: u64,
    /// NEST-6: dynamic instances whose schema is kept now
    /// (at most `--child-schema-cache`).
    pub names_kept: usize,
    /// NEST-11: calls the child made back into its service, in all.
    pub calls_back: u64,
    /// NEST-12: whether a live connection to the child is up now.
    pub up: bool,
}

/// A child's methods are data — its schema, asked at mount — not a Rust
/// enum: the [`Activation::Methods`] of a [`RemoteChild`].
#[derive(Debug, Clone, Copy)]
pub enum ChildMethods {}

impl schemars::JsonSchema for ChildMethods {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ChildMethods".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A child service's methods are data: its schema, asked when it was mounted (`<mount>.schema`)."
        })
    }
}

impl MethodEnumSchema for ChildMethods {
    fn method_names() -> &'static [&'static str] {
        &[]
    }

    fn schema_with_consts() -> Value {
        serde_json::to_value(schemars::schema_for!(ChildMethods)).unwrap_or(Value::Null)
    }
}

struct Inner {
    shared: Arc<Shared>,
    schema: PluginSchema,
    /// NEST-4: every static child below the mount, by dotted path relative
    /// to it (`a`, `a.b`), each schema as the child published it — its own
    /// namespace, its grants and roles relative to it, as an in-process
    /// child's ([`Activation::static_child_schemas`]).
    nodes: Vec<(String, PluginSchema)>,
    timings: MountTimings,
    /// NEST-6: each dynamic instance's schema, asked once per name.
    names: names::Names,
    /// NEST-16: what the child needs of its service: its own schema's
    /// `needs` and every static child's, as one list (`None`: none declares).
    needs: Option<Vec<crate::plexus::schema::Need>>,
}

impl Inner {
    pub(super) fn new(shared: Arc<Shared>, schema: PluginSchema, nodes: Vec<(String, PluginSchema)>, timings: MountTimings) -> Self {
        let names = names::Names::new(shared.opts.schema_cache);
        let declared = schema.needs.is_some() || nodes.iter().any(|(_, n)| n.needs.is_some());
        let mut needs: Vec<crate::plexus::schema::Need> = schema.needs.iter().chain(nodes.iter().filter_map(|(_, n)| n.needs.as_ref())).flatten().cloned().collect();
        needs.sort();
        needs.dedup_by(|a, b| a.method == b.method);
        let needs = declared.then_some(needs);
        Self { shared, schema, nodes, timings, names, needs }
    }
}

/// An activation in another process (or behind a WebSocket), mounted under
/// its [`ChildSpec`]'s name. Cheap to clone; the child stops when the last
/// clone is dropped.
#[derive(Clone)]
pub struct RemoteChild {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for RemoteChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteChild").field("spec", &self.inner.shared.spec.to_string()).field("stats", &self.stats()).finish()
    }
}

/// One schema as a child published it, read into 0.8's shape.
fn read_schema(raw: Value) -> Result<PluginSchema, String> {
    serde_json::from_value(peer::schema(raw)?).map_err(|e| format!("its schema does not read: {e}"))
}

/// A static child's schema as the mount keeps it (NEST-4): as published,
/// its grants relative to it — the host qualifies them by the path
/// ([`super::children::qualified`]), as it does an in-process child's.
pub(super) fn node_schema(path: &str, raw: Value) -> Result<PluginSchema, String> {
    read_schema(raw).map_err(|e| format!("its child `{path}`: {e}"))
}

/// The child's schema as the service keeps it: under the mount name, its
/// roles' grants and its methods' own grants requalified (`{ns}.m` →
/// `<mount>.m`). Its static children are kept beside it ([`node_schema`]);
/// a dynamic child's role (and a peer slot's) stays on it with the slot's
/// type: the slot a call into it is forwarded through (NEST-6).
fn mount_schema(name: &str, raw: Value) -> Result<PluginSchema, String> {
    let mut schema = read_schema(raw)?;
    if schema.namespace != name {
        tracing::info!(target: "plexus::child", child = %name, declared = %schema.namespace, "mounted under its mount name, not the namespace it declares");
    }
    let prefix = format!("{}.", schema.namespace);
    let requalify = |g: &String| match g.strip_prefix(&prefix) {
        Some(m) => format!("{name}.{m}"),
        None => format!("{name}.{g}"),
    };
    schema.roles = schema.roles.iter().map(|(r, gs)| (r.clone(), gs.iter().map(requalify).collect())).collect();
    for m in schema.methods.iter_mut() {
        if let Some(g) = m.grant.as_ref() {
            m.grant = Some(requalify(g));
        }
    }
    schema.namespace = name.to_string();
    Ok(schema)
}

impl RemoteChild {
    /// Start (or dial) the child, ask its `_info` and its schema within
    /// `opts.timeout`, and keep the connection. Fails naming the child and
    /// why: it did not start, did not answer, or published a schema the
    /// service will not mount.
    pub async fn connect(spec: ChildSpec, opts: ChildOptions) -> Result<Self, ChildError> {
        let name = spec.name().to_string();
        let start = |why: String| ChildError::Start(name.clone(), why);
        if opts.max_calls == 0 || opts.buffer == 0 {
            return Err(start("max_calls and buffer are at least 1".into()));
        }
        let principal = Self::principal_for(&spec, &opts).map_err(start)?;
        let shared = Shared::new(spec, opts, principal);
        let (conn, kept, mut timings) = shared.connect_once().await.map_err(start)?;
        let t = Instant::now();
        let hash = kept.hash();
        let read = mount_schema(&name, kept.top).and_then(|schema| {
            let nodes = kept.nodes.into_iter().map(|(path, raw)| node_schema(&path, raw).map(|s| (path, s))).collect::<Result<Vec<_>, _>>()?;
            Ok((schema, nodes))
        });
        let (schema, nodes) = match read {
            Ok(s) => s,
            Err(why) => {
                conn.shutdown.notify_one();
                return Err(start(why));
            }
        };
        let _ = shared.mounted_hash.set(hash);
        let _ = shared.identity.set(PeerIdentity::of(&conn));
        shared.install(conn);
        timings.merge_ms = t.elapsed().as_secs_f64() * 1e3;
        tracing::info!(target: "plexus::child", child = %name, spawn_ms = timings.spawn_ms, schema_ms = timings.schema_ms, merge_ms = timings.merge_ms, methods = schema.methods.len(), children = nodes.len(), "child mounted");
        let inner = Inner::new(shared, schema, nodes, timings);
        // NEST-16: the child's calls back are held to what it needs.
        inner.shared.upcalls.set_needs(inner.needs.as_deref());
        Ok(Self { inner: Arc::new(inner) })
    }

    #[allow(unused_variables)]
    fn principal_for(spec: &ChildSpec, opts: &ChildOptions) -> Result<String, String> {
        #[cfg(feature = "child-ws")]
        if let (ChildSpec::Ws { .. }, Some(path)) = (spec, &opts.key) {
            return Ok(ws::principal_of(&ws::read_seed(path)?));
        }
        Ok(opts.principal.clone())
    }

    /// What the seam has seen.
    pub fn stats(&self) -> ChildStats {
        let c: &Counters = &self.inner.shared.counters;
        ChildStats {
            open: c.open.load(Ordering::Relaxed),
            unasked: c.unasked.load(Ordering::Relaxed),
            restarts: c.restarts.load(Ordering::Relaxed),
            calls: c.calls.load(Ordering::Relaxed),
            name_schemas: self.inner.names.hops.load(Ordering::Relaxed),
            name_schema_hits: self.inner.names.hits.load(Ordering::Relaxed),
            names_kept: self.inner.names.len(c.restarts.load(Ordering::Relaxed)),
            calls_back: self.inner.shared.upcalls.made.load(Ordering::Relaxed),
            up: self.inner.shared.is_up(),
        }
    }

    /// DYNAUTH-8 (TM-3): who the child proved it was when it was mounted —
    /// pinned for the life of this mount: a restart (or redial) that proves
    /// another is refused for good ([`RemoteChild::dead`]).
    pub fn identity(&self) -> Option<&PeerIdentity> {
        self.inner.shared.identity.get()
    }

    /// DYNAUTH-5: hold the child's calls back to the needs an admin
    /// consented to, each on its scopes (`None`: no consent kept — every
    /// declared need, as NEST-16 has it). A declared need not consented is
    /// refused `forbidden` (`not_needed`), saying so.
    pub fn set_consent(&self, consent: Option<Vec<Consented>>) {
        self.inner.shared.upcalls.set_consent(consent);
    }

    /// DYNAUTH-5: the consent this mount holds its child's calls back to.
    pub fn consent(&self) -> Option<Vec<Consented>> {
        self.inner.shared.upcalls.consent().map(|c| c.to_vec())
    }

    /// DYNAUTH-7: revoke the child: from now no call is forwarded to it (so
    /// no token is minted for it), and every call it is making back ends
    /// with one error item saying `why`. A token already in its hand lives
    /// out its `exp` (≤ 60 s) at a peer that verifies without asking.
    pub fn revoke(&self, why: &str) {
        *self.inner.shared.revoked.lock().unwrap() = Some(why.to_string());
        self.inner.shared.upcalls.end_all(&format!("revoked: {why}"));
        tracing::warn!(target: "plexus::audit", child = %self.name(), %why, "child revoked");
    }

    /// DYNAUTH-7: why the child is revoked, if it is.
    pub fn revoked(&self) -> Option<String> {
        self.inner.shared.revoked.lock().unwrap().clone()
    }

    /// DYNAUTH-5: the Ed25519 key the child proved at its mount
    /// (`key:<hex>`), if it proved one; pinned with [`Self::identity`].
    pub fn peer_key(&self) -> Option<&str> {
        self.identity().and_then(|i| i.key.as_deref())
    }

    /// NEST-12: whether a live connection to the child is up now.
    pub fn is_up(&self) -> bool {
        self.inner.shared.is_up()
    }

    /// NEST-12: why the child will never be mounted again under this
    /// mount, if it will not — a restart published another schema
    /// (`"schema changed; restart the service"`): a fresh
    /// [`RemoteChild::connect`] mounts the new one.
    pub fn dead(&self) -> Option<String> {
        self.inner.shared.dead()
    }

    /// NEST-12: why the child is down, when it is — its last connection's
    /// end, the last start that failed, or why it will never be mounted
    /// again; `None` while it is up.
    pub fn why_down(&self) -> Option<String> {
        self.inner.shared.why_down()
    }

    /// NEST-12: bring the child up now if it is down — start (or redial) it
    /// within its [`Backoff`], as the next call would. `Err`: why it is not
    /// up (and [`RemoteChild::dead`] says whether it never will be).
    pub async fn up(&self) -> Result<(), String> {
        match self.inner.shared.ensure().await {
            Ok(_) => Ok(()),
            Err(PlexusStreamItem::Error { message, error, .. }) => Err(match error {
                plexus_client::RemoteError::ChildUnavailable { reason, .. } => reason,
                _ => message,
            }),
            Err(other) => Err(format!("{other:?}")),
        }
    }

    /// NEST-16: what the child's schema says it needs of the service it is
    /// mounted in (`None`: it declares nothing).
    pub fn needs(&self) -> Option<&[crate::plexus::schema::Need]> {
        self.inner.needs.as_deref()
    }

    /// NEST-11: forwarded calls open now that the child may call back under.
    pub fn calls_open_back(&self) -> usize {
        self.inner.shared.upcalls.open_now()
    }

    /// The schema hash this mount took, as the child published it (its
    /// whole tree's, NEST-4).
    pub fn mounted_hash(&self) -> &str {
        self.inner.shared.mounted_hash.get().map(String::as_str).unwrap_or_default()
    }

    /// The process now serving (a stdio child), if one is up.
    pub fn pid(&self) -> Option<u32> {
        self.inner.shared.current().and_then(|c| c.pid)
    }

    /// The mount's name.
    pub fn name(&self) -> &str {
        &self.inner.shared.name
    }

    /// The spec it was mounted from.
    pub fn spec(&self) -> &ChildSpec {
        &self.inner.shared.spec
    }

    /// The hop's `principal`: the service acting, as this child is told.
    pub fn principal(&self) -> &str {
        &self.inner.shared.principal
    }

    /// How long the mount took.
    pub fn mount_timings(&self) -> MountTimings {
        self.inner.timings
    }

    /// Subscriptions routed on the live connection (0 when none is up).
    pub fn routed(&self) -> usize {
        self.inner.shared.current().map_or(0, |c| c.routed())
    }

    /// The hop (spec/12) for a call by `auth`, decided as `reach`: the
    /// service acts, the caller is named `for`, the verdict is the limit.
    /// Nothing of the caller's credential.
    fn hop(&self, conn: &Conn, auth: Option<&AuthContext>, reach: &Reach, method: &str) -> (Value, String) {
        let for_: Vec<String> = auth.and_then(|a| a.principal()).map(|p| p.to_string()).into_iter().collect();
        let limit = reach.grant().map(|g| {
            let grant = match g.as_str().strip_prefix(&format!("{}.", self.name())) {
                Some(m) => format!("{}.{m}", conn.ns()),
                // NEST-12: a grant decided above the mount — the mount is a
                // peer reached through a slot of its service (`dyn.{peer}`,
                // or a literal `dyn.peer.<name>.<method>`): the verdict
                // covers this method, said in the child's terms.
                None => format!("{}.{method}", conn.ns()),
            };
            let held_on: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
            json!({ "grant": grant, "held_on": held_on })
        });
        let call = uuid::Uuid::new_v4().to_string();
        (json!({ "principal": self.inner.shared.principal, "for": for_, "limit": limit, "call": call }), call)
    }

    /// DYNAUTH-12: mint the token for one forwarded call — for a signed-in
    /// caller, when the service issues tokens, to a child that proved a key
    /// (bound to it) or one on the service's own pipe (`pipe:<name>`). A
    /// WebSocket child that proved no key gets none.
    fn mint(&self, auth: Option<&AuthContext>, reach: &Reach, hop: &Value, path: &str, call: &str) -> Result<Option<upcall::Minted>, String> {
        use crate::plexus::peer_token::{mint_scope, onward_scope, MintRequest};
        let Some(issuer) = self.inner.shared.opts.tokens.as_ref() else { return Ok(None) };
        let Some(sub) = auth.and_then(|a| a.principal()).map(|p| p.to_string()) else { return Ok(None) };
        let peer_key = self.peer_key().map(str::to_string);
        if peer_key.is_none() && !matches!(self.spec(), ChildSpec::Stdio { .. }) {
            return Ok(None);
        }
        let held: Vec<String> = if reach.is_everywhere() { vec!["*".into()] } else { reach.held_on().iter().map(|s| s.to_string()).collect() };
        let needs = crate::plexus::service_scope::current()
            .and_then(|w| w.upgrade())
            .map(|svc| self.inner.shared.upcalls.need_grants(&svc))
            .unwrap_or_default();
        let forwarded = hop.get("limit").and_then(|l| l.get("grant")).and_then(Value::as_str);
        let presented = upcall::presented();
        // DYNAUTH-6: onward from a call back, never wider than its token.
        let scope = match &presented {
            Some(p) => onward_scope(p, reach.grant().map(|g| g.as_str()), forwarded, &held, &needs),
            None => mint_scope(forwarded, &held, &needs),
        };
        let req = MintRequest { sub, peer_key, name: self.name().to_string(), scope, call: call.to_string(), method: path.to_string(), presented };
        let (token, claims) = issuer.mint(req).map_err(|e| e.to_string())?;
        Ok(Some(upcall::Minted { token, claims }))
    }

    /// NEST-4: the kept static child at `path` (dotted, relative to the mount).
    fn node(&self, path: &str) -> Option<&PluginSchema> {
        self.inner.nodes.iter().find(|(p, _)| p == path).map(|(_, s)| s)
    }

    /// NEST-6: where a path below the mount enters a slot, if it does: the
    /// slot (`<mount>.<parent>.{<slot>}`) and the instance's path below the
    /// mount (`<parent>.<name>`; through a peer slot, which the path names,
    /// `<parent>.<slot>.<name>`). The deepest kept level the path starts with
    /// is the parent: a static child, which the walk kept, wins over a slot.
    fn slot_of(&self, path: &str) -> Option<(String, String)> {
        let segs: Vec<&str> = path.split('.').collect();
        let (n, schema) = (1..segs.len())
            .rev()
            .find_map(|n| self.node(&segs[..n].join(".")).map(|s| (n, s)))
            .unwrap_or((0, &self.inner.schema));
        let parent = std::iter::once(self.name()).chain(segs[..n].iter().copied()).collect::<Vec<_>>().join(".");
        let next = segs[n];
        // NEST-7: a peer slot is named in the path, then the peer's name.
        if schema.methods.iter().any(|m| m.name == next && matches!(m.role, MethodRole::Peer { .. })) {
            return Some((crate::plexus::slots::slot_path(&parent, next), segs[..(n + 2).min(segs.len())].join(".")));
        }
        let slot = schema.methods.iter().find(|m| matches!(m.role, MethodRole::DynamicChild { .. }))?;
        Some((crate::plexus::slots::slot_path(&parent, &slot.name), segs[..=n].join(".")))
    }

    /// A path no kept level answers and no slot is on the way of.
    fn unreached(&self, method: &str) -> PlexusError {
        PlexusError::MethodNotFound { activation: self.name().to_string(), method: method.to_string() }
    }

    /// NEST-6: `<mount>.<path>.schema` where `path` is in a dynamic slot
    /// (`instance` its name's path): from the kept names, else asked of the
    /// child once (`{ns}.<path>.schema`, with the caller's hop), kept under
    /// its path and the `plexus_hash` it came with, and answered from that.
    /// What the child answers instead of a schema (an unknown name's
    /// not-found) comes back unchanged and is not kept.
    async fn name_schema(&self, path: &str, params: &Value, auth: Option<&AuthContext>) -> PlexusStream {
        let epoch = self.inner.shared.counters.restarts.load(Ordering::Relaxed);
        if let Some(s) = self.inner.names.get(path, epoch) {
            return self.schema_stream_of(&s, &s.namespace, params);
        }
        self.inner.names.crossed();
        let items: Vec<PlexusStreamItem> = futures::StreamExt::collect(self.forward(&format!("{path}.schema"), json!({}), auth, None).await).await;
        let kept = items.iter().find_map(|i| match i {
            PlexusStreamItem::Data { metadata, content, .. } => Some((metadata.plexus_hash.clone(), content.clone().into_value())),
            _ => None,
        });
        let Some((seen, raw)) = kept else {
            return Box::pin(futures::stream::iter(items));
        };
        match read_schema(raw) {
            Ok(schema) => {
                // A restart while it crossed: what came is the new child's.
                let epoch = self.inner.shared.counters.restarts.load(Ordering::Relaxed);
                self.inner.names.put(path, schema.clone(), seen, epoch);
                self.schema_stream_of(&schema, &schema.namespace, params)
            }
            Err(_) => Box::pin(futures::stream::iter(items)),
        }
    }

    fn schema_stream(&self, params: &Value) -> PlexusStream {
        self.schema_stream_of(&self.inner.schema, self.name(), params)
    }

    /// `schema` answered from what the mount kept: nothing crosses the hop
    /// (spec/12 rule 7). `label` is the content type's namespace.
    fn schema_stream_of(&self, schema: &PluginSchema, label: &str, params: &Value) -> PlexusStream {
        let ns = label.to_string();
        let content = match params.get("method").and_then(Value::as_str) {
            Some(m) => match schema.methods.iter().find(|x| x.name == m) {
                Some(ms) => serde_json::to_value(ms).unwrap_or_default(),
                None => {
                    let error = plexus_client::RemoteError::MethodNotFound { activation: ns.clone(), method: m.to_string() };
                    let mut e = PlexusStreamItem::error(meta(&ns), error, false);
                    if let PlexusStreamItem::Error { message, code, .. } = &mut e {
                        *message = format!("Method '{m}' not found");
                        *code = Some("-32602".into());
                    }
                    return Box::pin(futures::stream::iter([e]));
                }
            },
            None => serde_json::to_value(schema).unwrap_or_default(),
        };
        Box::pin(futures::stream::iter([
            PlexusStreamItem::Data { metadata: meta(&ns).into(), content_type: format!("{ns}.schema").into(), content: content.into() },
            PlexusStreamItem::Done { metadata: meta(&ns) },
        ]))
    }

    /// `instance`: the path of the dynamic instance the call goes through
    /// (NEST-6), whose kept schema an item with another `plexus_hash` drops.
    async fn forward(&self, method: &str, params: Value, auth: Option<&AuthContext>, instance: Option<String>) -> PlexusStream {
        let shared = &self.inner.shared;
        let one = |item: PlexusStreamItem| -> PlexusStream { Box::pin(futures::stream::iter([item])) };
        // DYNAUTH-7: a revoked child is forwarded nothing.
        if let Some(why) = shared.revoked.lock().unwrap().clone() {
            let e = PlexusError::Unauthenticated(format!("`{}` is revoked ({why}): no call is forwarded to it", self.name()));
            return one(PlexusStreamItem::from_plexus_error(meta(self.name()), &e, false));
        }
        // RETURNS-47: the verdict is the call's; outside one (a forward no
        // dispatch admitted) nothing crosses — fail closed, never everywhere.
        let reach = match super::grant_gate::current_reach() {
            Ok(reach) => reach,
            Err(e) => return one(PlexusStreamItem::from_plexus_error(meta(self.name()), &e, false)),
        };
        let max = shared.opts.max_calls;
        if shared.counters.open.fetch_add(1, Ordering::AcqRel) >= max {
            shared.counters.open.fetch_sub(1, Ordering::AcqRel);
            return one(too_many(self.name(), max));
        }
        let guard = OpenGuard(Arc::clone(&shared.counters));
        let conn = match shared.ensure().await {
            Ok(c) => c,
            Err(item) => return one(item),
        };
        shared.counters.calls.fetch_add(1, Ordering::Relaxed);
        let (mut hop, call_id) = self.hop(&conn, auth, &reach, method);
        let path = format!("{}.{method}", conn.ns());
        // DYNAUTH-12: the token for this one call, when the service issues.
        let minted = match self.mint(auth, &reach, &hop, &path, &call_id) {
            Ok(m) => m,
            Err(why) => {
                let e = PlexusError::Unauthenticated(format!("no token could be minted for `{}`: {why}", self.name()));
                return one(PlexusStreamItem::from_plexus_error(meta(self.name()), &e, false));
            }
        };
        if let Some(m) = &minted {
            hop["token"] = json!(m.token);
        }
        // NEST-11: the child may call back under this call while it is open.
        let under = shared.upcalls.open(&call_id, auth, &reach, minted);
        let call = json!({ "method": path, "params": params, "hop": hop });
        match conn.open(&format!("{}.call", conn.ns()), call, shared.opts.timeout).await {
            Ok((sid, rx)) => {
                let generation = reach.generation().cloned();
                let seen = generation.as_ref().map_or(0, GrantsGeneration::current);
                let instance = instance.map(|path| (Arc::clone(&self.inner), path));
                Box::pin(CallStream { rx, sid, conn, over: false, _guard: guard, reach, generation, seen, name: self.name().to_string(), instance, under })
            }
            Err(item) => one(item),
        }
    }
}

/// One open call, counted until its stream ends or is dropped.
struct OpenGuard(Arc<Counters>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The stream the service hands its caller: the child's items, in order,
/// until the first terminal one; dropped before it, the child is told.
struct CallStream {
    rx: mpsc::Receiver<PlexusStreamItem>,
    sid: SubKey,
    conn: Arc<Conn>,
    over: bool,
    _guard: OpenGuard,
    /// The gate's verdict at the open, asked again when the grants
    /// generation moves (BIDIR-1 `regate = generation`, BIDIR-8).
    reach: Reach,
    generation: Option<GrantsGeneration>,
    seen: u64,
    name: String,
    /// NEST-6: the dynamic instance the call goes through, and the mount
    /// whose kept schema of it an item with another `plexus_hash` drops.
    instance: Option<(Arc<Inner>, String)>,
    /// NEST-11: the child's standing to call back under this call; ended
    /// with it.
    under: Option<upcall::UnderGuard>,
}

impl CallStream {
    /// The call is over: what the child made under it ends too.
    fn finish(&mut self, why: &str) {
        self.over = true;
        if let Some(u) = self.under.take() {
            u.end(why);
        }
    }

    /// The grant revoked mid-stream: the caller's last item.
    fn revoked(&self) -> PlexusStreamItem {
        let grant = self.reach.grant().map(|g| g.as_str().to_string()).unwrap_or_default();
        let error = plexus_client::RemoteError::Forbidden {
            reason: plexus_client::DenyReason::MissingGrant {
                grant: grant.clone(),
                scope: "*".into(),
                roles: Vec::new(),
                held_on: Vec::new(),
            },
        };
        let mut item = PlexusStreamItem::error(meta(&self.name), error, false);
        if let PlexusStreamItem::Error { message, .. } = &mut item {
            *message = format!("Forbidden: `{grant}` is no longer held — the call's grant moved while it ran");
        }
        item
    }
}

impl Stream for CallStream {
    type Item = PlexusStreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.over {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(item)) => {
                if let (Some((inner, path)), Some(m)) = (&self.instance, item.metadata()) {
                    inner.names.observe(path, &m.plexus_hash);
                }
                let terminal = matches!(item, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. });
                let moved = self.generation.as_ref().map(GrantsGeneration::current).filter(|g| *g != self.seen);
                if let (false, Some(g)) = (terminal, moved) {
                    self.seen = g;
                    if self.reach.current().is_none() {
                        let sid = self.sid.clone();
                        self.conn.unsubscribe(&sid);
                        self.finish("its grant was revoked");
                        return Poll::Ready(Some(self.revoked()));
                    }
                }
                if terminal {
                    self.finish("it ended");
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                // The channel closed with no terminal item: the link went.
                self.finish("the connection closed");
                Poll::Ready(Some(unavailable(&self.name, "the connection closed")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CallStream {
    fn drop(&mut self) {
        if !self.over {
            self.conn.unsubscribe(&self.sid);
        }
    }
}

#[async_trait]
impl Activation for RemoteChild {
    type Methods = ChildMethods;

    fn needs(&self) -> Option<Vec<crate::plexus::schema::Need>> {
        self.inner.needs.clone()
    }

    fn namespace(&self) -> &str {
        self.name()
    }

    fn version(&self) -> &str {
        &self.inner.schema.version
    }

    fn description(&self) -> &str {
        &self.inner.schema.description
    }

    fn long_description(&self) -> Option<&str> {
        self.inner.schema.long_description.as_deref()
    }

    fn methods(&self) -> Vec<&str> {
        self.inner.schema.methods.iter().map(|m| m.name.as_str()).collect()
    }

    fn method_help(&self, method: &str) -> Option<String> {
        self.inner.schema.methods.iter().find(|m| m.name == method).map(|m| m.description.clone())
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>, _raw: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        if method == "schema" {
            return Ok(self.schema_stream(&params));
        }
        // NEST-4: a static child's schema, from the kept tree.
        if let Some(path) = method.strip_suffix(".schema") {
            if let Some(s) = self.node(path) {
                return Ok(self.schema_stream_of(s, &s.namespace, &params));
            }
            // NEST-6: an instance in a dynamic slot: the one schema that
            // crosses the hop, once per name (spec/12 rule 7's exception).
            return match self.slot_of(path) {
                Some(_) => Ok(self.name_schema(path, &params, auth).await),
                None => Err(self.unreached(method)),
            };
        }
        let found = match method.rsplit_once('.') {
            // NEST-4: a static child's method, by its path.
            Some((path, name)) => match self.node(path) {
                Some(s) => s.methods.iter().find(|m| m.name == name && m.role == MethodRole::Rpc),
                // NEST-6: a method of an instance in a dynamic slot: the
                // host's gate decided it on the slot grant; forwarded as
                // any call, the child deciding again and answering an
                // unknown name with its own not-found.
                None => match self.slot_of(path) {
                    Some((_, instance)) => return Ok(self.forward(method, params, auth, Some(instance)).await),
                    None => return Err(self.unreached(method)),
                },
            },
            None => self.inner.schema.methods.iter().find(|m| m.name == method && m.role == MethodRole::Rpc),
        };
        let Some(m) = found else {
            return Err(PlexusError::MethodNotFound { activation: self.name().to_string(), method: method.to_string() });
        };
        // BIDIR-6: a hop forwards no input half yet; the far side would wait
        // for items that never come.
        if m.input.is_some() {
            return Err(PlexusError::ExecutionError(format!(
                "`{}.{method}` takes an input stream, and a hop to a remote child does not forward one yet",
                self.name()
            )));
        }
        Ok(self.forward(method, params, auth, None).await)
    }

    /// Nothing of its own on the socket: a child is reached through the
    /// service's `{service}.call`, behind its gate.
    fn into_rpc_methods(self) -> jsonrpsee::Methods {
        jsonrpsee::Methods::new()
    }

    fn plugin_schema(&self) -> PluginSchema {
        self.inner.schema.clone()
    }

    /// NEST-4: the kept tree — the host gates, lists and describes a mounted
    /// child's children by their whole path, as it does an in-process
    /// child's (MACRO-20, [`super::children`]).
    fn static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        self.inner.nodes.clone()
    }
}

#[async_trait]
impl ChildRouter for RemoteChild {
    fn router_namespace(&self) -> &str {
        self.name()
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

    fn router_static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        self.inner.nodes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(methods: Value, roles: Value) -> Value {
        json!({ "namespace": "stub", "version": "0.1.0", "description": "d", "self_hash": "h", "hash": "h", "methods": methods, "roles": roles })
    }

    fn m(name: &str) -> Value {
        json!({ "name": name, "description": "", "hash": "x", "streaming": false, "bidirectional": false })
    }

    /// RETURNS-36 (review #6): no guessing — a method that states neither
    /// `cardinality` (0.8) nor `streaming` (0.7.0) is refused, naming it, as
    /// plexus-protocol's `cardinalityOf` refuses it.
    #[test]
    fn a_method_stating_neither_cardinality_nor_streaming_is_refused() {
        let silent = json!({ "name": "quiet", "description": "", "hash": "x" });
        let e = mount_schema("echo", raw(json!([m("echo"), silent]), json!({}))).unwrap_err();
        assert!(e.contains("`quiet`") && e.contains("neither cardinality"), "{e}");
    }

    #[test]
    fn the_mount_name_wins_and_roles_are_requalified() {
        let s = mount_schema("echo", raw(json!([m("echo"), m("shout")]), json!({ "viewer": ["stub.echo"], "editor": ["stub.echo", "stub.shout"] }))).unwrap();
        assert_eq!(s.namespace, "echo");
        assert_eq!(s.roles["viewer"], vec!["echo.echo".to_string()]);
        assert_eq!(s.roles["editor"], vec!["echo.echo".to_string(), "echo.shout".to_string()]);
    }

    /// NEST-4: a child with children mounts; its child roles stay on it.
    #[test]
    fn a_child_with_children_mounts_and_its_method_grants_are_requalified() {
        let mut inner = m("inner");
        inner["role"] = json!({ "kind": "static_child" });
        let mut own = m("echo");
        own["grant"] = json!("stub.echo");
        let s = mount_schema("echo", raw(json!([own, inner]), json!({}))).unwrap();
        assert_eq!(s.methods[0].grant.as_deref(), Some("echo.echo"));
        assert_eq!(s.methods[1].role, MethodRole::StaticChild);
        let mut slot = m("item");
        slot["role"] = json!({ "kind": "dynamic_child", "list_method": "names" });
        let nested = raw(json!([m("echo"), s_inner(), slot]), json!({}));
        assert_eq!(link::static_children(&nested), vec!["inner".to_string()], "a dynamic child is a slot, not walked");
        // A service's root says its activations in `children` alone.
        let mut root = raw(json!([m("call")]), json!({}));
        root["children"] = json!([{ "namespace": "greeter", "description": "", "hash": "g" }]);
        assert_eq!(link::static_children(&root), vec!["greeter".to_string()]);
    }

    fn s_inner() -> Value {
        let mut inner = m("inner");
        inner["role"] = json!({ "kind": "static_child" });
        inner
    }

    /// NEST-4: the tree's hash moves with a grandchild's.
    #[test]
    fn the_tree_hash_covers_every_level() {
        let top = raw(json!([m("echo")]), json!({}));
        let flat = link::Kept { top: top.clone(), nodes: vec![] };
        assert_eq!(flat.hash(), link::schema_hash(&top), "a flat child's hash is its schema's, as before");
        let mut c = raw(json!([m("m")]), json!({}));
        let one = link::Kept { top: top.clone(), nodes: vec![("a.b".into(), c.clone())] }.hash();
        c["hash"] = json!("other");
        let two = link::Kept { top, nodes: vec![("a.b".into(), c)] }.hash();
        assert_ne!(one, two);
    }

    #[test]
    fn typed_error_fields_cross_whole() {
        let item = unavailable("echo", "gone");
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["error_kind"], "child_unavailable");
        assert_eq!(v["code"], "child_unavailable");
        assert_eq!(v["child"], "echo");
        let back: PlexusStreamItem = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back.error_kind(), Some("child_unavailable"));
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        // An error spec/05 gives no kind carries no `error_kind`: its keys
        // are spec/05's four and RETURNS-6's typed `error` (RETURNS-36).
        let plain = PlexusStreamItem::error(meta("x"), plexus_client::RemoteError::Execution { message: "m".into() }, false);
        let pv = serde_json::to_value(&plain).unwrap();
        let keys: Vec<_> = pv.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["code", "error", "message", "metadata", "recoverable", "type"]);
    }
}
