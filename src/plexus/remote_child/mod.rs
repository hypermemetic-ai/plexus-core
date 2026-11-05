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

// RETURNS-47: the far side in Rust — an activation served as a child, each
// call in its hop's context.
mod host;
mod link;
// RETURNS-36: a peer on plexus-wire's spec as main wrote it, read as 0.8.
mod peer;
mod spec;
#[cfg(feature = "child-ws")]
mod ws;
#[cfg(feature = "clap")]
mod args;

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

pub use host::{serve_child, serve_child_stdio};
pub use link::MountTimings;
pub use spec::{parse_duration, Backoff, ChildError, ChildOptions, ChildSpec};
#[cfg(feature = "clap")]
pub use args::ChildArgs;

use link::{meta, too_many, unavailable, Conn, Counters, Shared, SubKey};

use super::auth::AuthContext;
use super::method_enum::MethodEnumSchema;
use super::plexus::{Activation, ChildRouter, PlexusError};
use super::schema::{MethodRole, PluginSchema};
use super::streaming::PlexusStream;
use super::types::PlexusStreamItem;

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
    timings: MountTimings,
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

/// The child's schema as the service keeps it: under the mount name, its
/// roles' grants requalified (`{ns}.m` → `<mount>.m`). A child mounting
/// children of its own is refused, naming the method.
fn mount_schema(name: &str, raw: Value) -> Result<PluginSchema, String> {
    let mut schema: PluginSchema = serde_json::from_value(peer::schema(raw)?).map_err(|e| format!("its schema does not read: {e}"))?;
    if let Some(m) = schema.methods.iter().find(|m| m.role != MethodRole::Rpc) {
        return Err(format!("its method `{}` is a child ({:?}): a child mounting children is not served", m.name, m.role));
    }
    #[allow(deprecated)] // IR-4: the side-table, still on the wire
    if schema.children.as_ref().is_some_and(|c| !c.is_empty()) {
        return Err("its schema lists children: a child mounting children is not served".into());
    }
    if schema.namespace != name {
        tracing::info!(target: "plexus::child", child = %name, declared = %schema.namespace, "mounted under its mount name, not the namespace it declares");
    }
    let prefix = format!("{}.", schema.namespace);
    let requalify = |g: &String| match g.strip_prefix(&prefix) {
        Some(m) => format!("{name}.{m}"),
        None => format!("{name}.{g}"),
    };
    schema.roles = schema.roles.iter().map(|(r, gs)| (r.clone(), gs.iter().map(requalify).collect())).collect();
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
        let (conn, raw, mut timings) = shared.connect_once().await.map_err(start)?;
        let t = Instant::now();
        let hash = link::schema_hash(&raw);
        let schema = match mount_schema(&name, raw) {
            Ok(s) => s,
            Err(why) => {
                conn.shutdown.notify_one();
                return Err(start(why));
            }
        };
        let _ = shared.mounted_hash.set(hash);
        shared.install(conn);
        timings.merge_ms = t.elapsed().as_secs_f64() * 1e3;
        tracing::info!(target: "plexus::child", child = %name, spawn_ms = timings.spawn_ms, schema_ms = timings.schema_ms, merge_ms = timings.merge_ms, methods = schema.methods.len(), "child mounted");
        Ok(Self { inner: Arc::new(Inner { shared, schema, timings }) })
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
        }
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
    fn hop(&self, conn: &Conn, auth: Option<&AuthContext>, reach: &Reach) -> Value {
        let for_: Vec<String> = auth.and_then(|a| a.principal()).map(|p| p.to_string()).into_iter().collect();
        let limit = reach.grant().map(|g| {
            let grant = match g.as_str().strip_prefix(&format!("{}.", self.name())) {
                Some(m) => format!("{}.{m}", conn.ns()),
                None => g.as_str().to_string(),
            };
            let held_on: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
            json!({ "grant": grant, "held_on": held_on })
        });
        json!({ "principal": self.inner.shared.principal, "for": for_, "limit": limit, "call": uuid::Uuid::new_v4().to_string() })
    }

    fn schema_stream(&self, params: &Value) -> PlexusStream {
        let ns = self.name().to_string();
        let content = match params.get("method").and_then(Value::as_str) {
            Some(m) => match self.inner.schema.methods.iter().find(|x| x.name == m) {
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
            None => serde_json::to_value(&self.inner.schema).unwrap_or_default(),
        };
        Box::pin(futures::stream::iter([
            PlexusStreamItem::Data { metadata: meta(&ns).into(), content_type: format!("{ns}.schema").into(), content: content.into() },
            PlexusStreamItem::Done { metadata: meta(&ns) },
        ]))
    }

    async fn forward(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> PlexusStream {
        let shared = &self.inner.shared;
        let one = |item: PlexusStreamItem| -> PlexusStream { Box::pin(futures::stream::iter([item])) };
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
        let hop = self.hop(&conn, auth, &reach);
        let path = format!("{}.{method}", conn.ns());
        let call = json!({ "method": path, "params": params, "hop": hop });
        match conn.open(&format!("{}.call", conn.ns()), call, shared.opts.timeout).await {
            Ok((sid, rx)) => {
                let generation = reach.generation().cloned();
                let seen = generation.as_ref().map_or(0, GrantsGeneration::current);
                Box::pin(CallStream { rx, sid, conn, over: false, _guard: guard, reach, generation, seen, name: self.name().to_string() })
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
}

impl CallStream {
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
                let terminal = matches!(item, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. });
                let moved = self.generation.as_ref().map(GrantsGeneration::current).filter(|g| *g != self.seen);
                if let (false, Some(g)) = (terminal, moved) {
                    self.seen = g;
                    if self.reach.current().is_none() {
                        let sid = self.sid.clone();
                        self.conn.unsubscribe(&sid);
                        self.over = true;
                        return Poll::Ready(Some(self.revoked()));
                    }
                }
                if terminal {
                    self.over = true;
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                // The channel closed with no terminal item: the link went.
                self.over = true;
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
        let Some(m) = self.inner.schema.methods.iter().find(|m| m.name == method) else {
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
        Ok(self.forward(method, params, auth).await)
    }

    /// Nothing of its own on the socket: a child is reached through the
    /// service's `{service}.call`, behind its gate.
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

    #[test]
    fn a_child_with_children_is_refused_naming_the_method() {
        let mut inner = m("inner");
        inner["role"] = json!({ "kind": "static_child" });
        let e = mount_schema("echo", raw(json!([m("echo"), inner]), json!({}))).unwrap_err();
        assert!(e.contains("`inner`"), "{e}");
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
