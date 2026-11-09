//! NEST-16 · a graft that knows its parent.
//!
//! An activation written against its parent's interface —
//! `#[plexus_macros::activation(parent = ShopClient)]` — takes the parent's
//! client into a method as `parent: Parent<ShopClient>`, injected by the
//! server (never on the wire, never in its own client), and calls inward as
//! if the parent were local:
//!
//! ```ignore
//! #[plexus_macros::activation(parent = ShopClient)]
//! impl Restock {
//!     /// The items running low.
//!     pub async fn low(&self, parent: Parent<ShopClient>, under: u32) -> Vec<Item> {
//!         parent.items().collect::<Vec<_>>().await … // needs: [shop.items]
//!     }
//! }
//! ```
//!
//! The client runs over a [`ParentTransport`]: the mount's connection back to
//! the service (NEST-11's [`host()`](super::remote_child::host)) when the
//! child runs behind a mount, or the service's own routing when it is
//! registered in the same process. Either way each call is the original
//! caller's, through the service's gate.
//!
//! What the child calls of its parent is its schema's `needs` ([`Need`]),
//! which the macro infers from the method bodies. Three places hold to it:
//!
//! - **the graft** — mounting the child (a static `--child`, plexus-dyn's
//!   `connect`/`grow`, [`ServiceRoot::insert`](super::ServiceRoot::insert))
//!   checks each need against the service's own schema by the method's
//!   shape hash, refusing with every missing or changed method named
//!   ([`NeedsMiss`]);
//! - **the host** — a call the child makes up that is neither the standard
//!   upward interface ([`STANDARD`]) nor a need is refused, typed
//!   (`forbidden`, reason `not_needed`), and a need is routed with one more
//!   ceiling layer, its own grant (TM-1, DYNAUTH-4);
//! - **the client** — [`ParentTransport`] refuses the same before sending.

use std::ops::Deref;
use std::sync::Arc;

use futures::StreamExt;
use plexus_client::{DenyReason, ItemStream, MethodRef, RemoteError, StreamItem, Transport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::auth::AuthContext;
use super::hub_transport::HubTransport;
use super::in_process::to_client_item;
use super::peer::PeerError;
use super::plexus::{DynamicHub, PlexusError};
use super::schema::Need;
use super::types::{PlexusStreamItem, StreamMetadata};

/// `host.schema`: the service's whole description (also any `<path>.schema`).
pub const HOST_SCHEMA: &str = "host.schema";
/// `host.whoami`: whom the call the child is serving is for.
pub const HOST_WHOAMI: &str = "host.whoami";
/// `host.log { level, message }`: a line in the service's log.
pub const HOST_LOG: &str = "host.log";
/// `host.notify { topic, data }`: a message to the service
/// ([`DynamicHub::notices`]).
pub const HOST_NOTIFY: &str = "host.notify";

/// D10: the standard upward interface — what every child may call of its
/// service, with no declaration. Every other upward call is a [`Need`].
pub const STANDARD: [&str; 4] = [HOST_SCHEMA, HOST_WHOAMI, HOST_LOG, HOST_NOTIFY];

/// Whether `method` is one of the [`STANDARD`] four, or a schema read
/// (`<path>.schema`, which `host.schema` stands for).
pub fn is_standard(method: &str) -> bool {
    STANDARD.contains(&method) || method.ends_with(".schema")
}

/// What a child said to its service through `host.notify`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notice {
    /// The child, by its mount name (or its namespace, in process).
    pub child: String,
    /// What it is about.
    pub topic: String,
    /// Anything.
    #[serde(default)]
    pub data: Value,
    /// Whom the call it was serving was for, if anyone.
    #[serde(default, rename = "for", skip_serializing_if = "Option::is_none")]
    pub for_: Option<String>,
}

/// Why a graft was refused: what the child needs that the service does not
/// serve, or serves in another shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedsMiss {
    /// The child, by its name.
    pub child: String,
    /// The service it was to be grafted onto.
    pub service: String,
    /// Needs the service does not serve.
    pub missing: Vec<String>,
    /// Needs the service serves under another shape than the child was
    /// built against.
    pub changed: Vec<String>,
}

impl NeedsMiss {
    /// Every method named, missing first.
    pub fn methods(&self) -> Vec<String> {
        self.missing.iter().chain(self.changed.iter()).cloned().collect()
    }
}

impl std::fmt::Display for NeedsMiss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}` cannot be grafted onto `{}`:", self.child, self.service)?;
        if !self.missing.is_empty() {
            write!(f, " it needs {}, which `{}` does not serve", self.missing.join(", "), self.service)?;
        }
        if !self.changed.is_empty() {
            if !self.missing.is_empty() {
                f.write_str(";")?;
            }
            write!(f, " the shape of {} moved since it was built", self.changed.join(", "))?;
        }
        Ok(())
    }
}

impl std::error::Error for NeedsMiss {}

impl From<NeedsMiss> for PeerError {
    fn from(m: NeedsMiss) -> Self {
        PeerError::ShapeMismatch { wanted: format!("the needs of `{}`", m.child), got: m.service.clone(), methods: m.methods() }
    }
}

/// Check `needs` against what a service serves: `served(path)` is the shape
/// hash of the method at `path` (empty: served, its shape unknown — below an
/// untyped slot), `None` when it serves none there. An empty need hash
/// checks presence alone.
pub fn check_needs(child: &str, service: &str, needs: &[Need], served: impl Fn(&str) -> Option<String>) -> Result<(), NeedsMiss> {
    let (mut missing, mut changed) = (Vec::new(), Vec::new());
    for need in needs {
        if is_standard(&need.method) {
            continue;
        }
        match served(&need.method) {
            None => missing.push(need.method.clone()),
            Some(h) if !need.hash.is_empty() && !h.is_empty() && h != need.hash => changed.push(need.method.clone()),
            Some(_) => {}
        }
    }
    if missing.is_empty() && changed.is_empty() {
        Ok(())
    } else {
        Err(NeedsMiss { child: child.to_string(), service: service.to_string(), missing, changed })
    }
}

/// The refusal of an upward call outside the standard interface and the
/// child's needs.
pub fn not_needed(method: &str) -> PlexusError {
    PlexusError::Forbidden { reason: super::plexus::AuthzDenyReason::NotNeeded { method: method.to_string() } }
}

fn meta(child: &str) -> StreamMetadata {
    StreamMetadata::new(vec![child.to_string()], super::context::PlexusContext::hash())
}

/// The service's own answer to `host.whoami`, `host.log` or `host.notify`
/// from `child`, serving a call for `caller`: one data item, then done.
/// `None` for any other method.
pub(crate) fn standard_answer(service: &DynamicHub, child: &str, method: &str, params: &Value, caller: Option<&AuthContext>) -> Option<Vec<PlexusStreamItem>> {
    let who = caller.and_then(|a| a.principal()).map(|p| p.to_string());
    let content = match method {
        HOST_WHOAMI => json!({ "for": who, "child": child, "service": service.runtime_namespace() }),
        HOST_LOG => {
            let level = params.get("level").and_then(Value::as_str).unwrap_or("info");
            let message = params.get("message").and_then(Value::as_str).unwrap_or_default();
            match level {
                "error" => tracing::error!(target: "plexus::child", child = %child, r#for = ?who, "{message}"),
                "warn" => tracing::warn!(target: "plexus::child", child = %child, r#for = ?who, "{message}"),
                "debug" => tracing::debug!(target: "plexus::child", child = %child, r#for = ?who, "{message}"),
                "trace" => tracing::trace!(target: "plexus::child", child = %child, r#for = ?who, "{message}"),
                _ => tracing::info!(target: "plexus::child", child = %child, r#for = ?who, "{message}"),
            }
            json!({ "logged": true })
        }
        HOST_NOTIFY => {
            let notice = Notice {
                child: child.to_string(),
                topic: params.get("topic").and_then(Value::as_str).unwrap_or_default().to_string(),
                data: params.get("data").cloned().unwrap_or(Value::Null),
                for_: who,
            };
            let heard = service.notify(notice);
            json!({ "heard": heard })
        }
        _ => return None,
    };
    Some(vec![PlexusStreamItem::data(meta(child), method.to_string(), content), PlexusStreamItem::done(meta(child))])
}

/// How a [`Parent`] reaches its service.
#[derive(Clone)]
enum Route {
    /// Behind a mount: the connection back (NEST-11).
    #[cfg(not(target_arch = "wasm32"))]
    Host(super::remote_child::HostTransport),
    /// In the same process: the service's own routing, as the caller.
    Local(HubTransport),
}

/// A [`Transport`] to the service a graft is mounted in, for the methods it
/// needs and the standard upward interface alone.
#[derive(Clone)]
pub struct ParentTransport {
    route: Route,
    child: Arc<str>,
    needs: Arc<[String]>,
}

impl std::fmt::Debug for ParentTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let how = match &self.route {
            #[cfg(not(target_arch = "wasm32"))]
            Route::Host(_) => "host",
            Route::Local(_) => "local",
        };
        f.debug_struct("ParentTransport").field("child", &self.child).field("route", &how).field("needs", &self.needs).finish()
    }
}

fn refused(error: RemoteError, message: String) -> ItemStream<'static> {
    let item = StreamItem::Error { metadata: None, recoverable: false, message: Some(message), code: None, error, fields: Default::default() };
    Box::pin(futures::stream::once(async move { Ok(item) }))
}

impl ParentTransport {
    /// The service the call being run was routed in (or forwarded from):
    /// over the mount's connection back when there is one, else in process.
    /// `child` names the graft; `needs` are the method paths it may call
    /// beyond the standard interface.
    pub fn in_call(child: &str, needs: Arc<[String]>) -> Result<Self, PlexusError> {
        let ctx = crate::call::context().map_err(|e| PlexusError::ExecutionError(format!("`{child}` reaches its parent only inside a call: {e}")))?;
        #[cfg(not(target_arch = "wasm32"))]
        if ctx.host_link().is_some() {
            let t = super::remote_child::host().map_err(|e| PlexusError::ExecutionError(format!("`{child}`: {e}")))?;
            return Ok(Self { route: Route::Host(t), child: Arc::from(child), needs });
        }
        let service = super::service_scope::current().and_then(|s| s.upgrade()).ok_or_else(|| {
            PlexusError::ExecutionError(format!("`{child}` reaches its parent only in a call a service routed or forwarded"))
        })?;
        Ok(Self::local(Arc::new(service), ctx.auth().cloned(), child, needs))
    }

    /// In process: `service`'s own routing, every call as `caller`.
    pub fn local(service: Arc<DynamicHub>, caller: Option<AuthContext>, child: &str, needs: Arc<[String]>) -> Self {
        Self { route: Route::Local(HubTransport::with(service, caller)), child: Arc::from(child), needs }
    }

    /// The methods this transport may call beyond the standard interface.
    pub fn needs(&self) -> &[String] {
        &self.needs
    }

    /// Whether the transport goes over a mount's connection back.
    pub fn is_remote(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        if let Route::Host(_) = self.route {
            return true;
        }
        false
    }
}

impl Transport for ParentTransport {
    fn call(&self, method: MethodRef, params: Value) -> ItemStream<'_> {
        let q = method.qualified();
        if !is_standard(&q) && !self.needs.iter().any(|n| *n == q) {
            let e = not_needed(&q);
            return refused(RemoteError::Forbidden { reason: DenyReason::NotNeeded { method: q.clone() } }, e.to_string());
        }
        match &self.route {
            #[cfg(not(target_arch = "wasm32"))]
            Route::Host(t) => t.call(method, params),
            Route::Local(t) => {
                if let Some(items) = standard_answer(t.hub(), &self.child, &q, &params, t.caller()) {
                    return Box::pin(futures::stream::iter(items.into_iter().map(|i| Ok(to_client_item(i)))));
                }
                if q == HOST_SCHEMA {
                    let m = MethodRef::named(t.hub().runtime_namespace().to_string(), "schema");
                    return t.call(m, params);
                }
                t.call(method, params)
            }
        }
    }
}

/// Why an upward call through [`Upward`] failed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct UpwardError(pub String);

/// The standard upward interface (D10), every child's: [`Parent::host`].
pub struct Upward<'a> {
    t: &'a ParentTransport,
}

impl Upward<'_> {
    async fn one(&self, method: &'static str, params: Value) -> Result<Value, UpwardError> {
        let (path, name) = method.split_once('.').expect("a standard method is `host.<name>`");
        let mut s = self.t.call(MethodRef::named(path, name), params);
        while let Some(item) = s.next().await {
            match item {
                Ok(StreamItem::Data { content, .. }) => return Ok(content),
                Ok(StreamItem::Error { error, message, .. }) => return Err(UpwardError(message.unwrap_or_else(|| error.to_string()))),
                Ok(StreamItem::Done { .. }) => break,
                Ok(_) => {}
                Err(e) => return Err(UpwardError(e.to_string())),
            }
        }
        Err(UpwardError(format!("`{method}` answered nothing")))
    }

    /// `host.schema`: the service's description, as the caller may see it.
    pub async fn schema(&self) -> Result<Value, UpwardError> {
        self.one(HOST_SCHEMA, json!({})).await
    }

    /// `host.whoami`: `{ for, child, service }` — whom the call being served
    /// is for (`null`: no one signed in).
    pub async fn whoami(&self) -> Result<Value, UpwardError> {
        self.one(HOST_WHOAMI, json!({})).await
    }

    /// `host.log`: a line in the service's log at `level` (`error`, `warn`,
    /// `info`, `debug`, `trace`).
    pub async fn log(&self, level: &str, message: &str) -> Result<(), UpwardError> {
        self.one(HOST_LOG, json!({ "level": level, "message": message })).await.map(|_| ())
    }

    /// `host.notify`: tell the service something; answers how many in the
    /// service were listening ([`DynamicHub::notices`]).
    pub async fn notify(&self, topic: &str, data: Value) -> Result<u64, UpwardError> {
        self.one(HOST_NOTIFY, json!({ "topic": topic, "data": data })).await.map(|v| v["heard"].as_u64().unwrap_or(0))
    }
}

/// The parent's client, injected into a graft's method:
/// `parent: Parent<ShopClient>` (the macro writes the transport,
/// `ShopClient<ParentTransport>`). It derefs to the client, so
/// `parent.items()` is the parent's `items`; [`Parent::host`] is the
/// standard upward interface.
pub struct Parent<C> {
    client: C,
    transport: ParentTransport,
}

impl<C> Parent<C> {
    /// The parent `client` makes over `transport`.
    pub fn new(transport: ParentTransport, make: impl FnOnce(ParentTransport) -> C) -> Self {
        Self { client: make(transport.clone()), transport }
    }

    /// What the server injects: the parent of the call being run
    /// ([`ParentTransport::in_call`]), its client made by `make`.
    #[doc(hidden)]
    pub fn __in_call(child: &str, needs: Arc<[String]>, make: impl FnOnce(ParentTransport) -> C) -> Result<Self, PlexusError> {
        Ok(Self::new(ParentTransport::in_call(child, needs)?, make))
    }

    /// The parent's client.
    pub fn client(&self) -> &C {
        &self.client
    }

    /// The parent's client, owned.
    pub fn into_inner(self) -> C {
        self.client
    }

    /// The transport the client runs over.
    pub fn transport(&self) -> &ParentTransport {
        &self.transport
    }

    /// The standard upward interface: `host.schema`, `host.whoami`,
    /// `host.log`, `host.notify`.
    pub fn host(&self) -> Upward<'_> {
        Upward { t: &self.transport }
    }
}

impl<C> Deref for Parent<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.client
    }
}

impl<C: std::fmt::Debug> std::fmt::Debug for Parent<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parent").field("client", &self.client).field("transport", &self.transport).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_need_missing_or_moved_is_named() {
        let needs = [Need::new("shop.items", "aaaa"), Need::new("shop.price", "bbbb"), Need::new("shop.tags", ""), Need::new("host.whoami", "")];
        let served = |p: &str| match p {
            "shop.items" => Some("aaaa".to_string()),
            "shop.price" => Some("cccc".to_string()),
            _ => None,
        };
        let miss = check_needs("restock", "svc", &needs, served).unwrap_err();
        assert_eq!(miss.missing, ["shop.tags"]);
        assert_eq!(miss.changed, ["shop.price"]);
        let text = miss.to_string();
        assert!(text.contains("shop.tags") && text.contains("shop.price") && text.contains("restock"), "{text}");
        assert!(check_needs("restock", "svc", &needs[..1], served).is_ok());
    }

    #[test]
    fn the_standard_four_and_schemas_need_no_declaration() {
        for m in STANDARD {
            assert!(is_standard(m));
        }
        assert!(is_standard("shop.schema"));
        assert!(!is_standard("shop.items"));
        assert!(!is_standard("host.restart"));
    }
}
