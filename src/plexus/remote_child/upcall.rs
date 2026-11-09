//! NEST-11 · a child calls its service back, under a call it serves.
//!
//! While the service has a call open into a child, the child may open calls
//! of its own into the service on the same connection (spec/14: either side
//! opens a call), each naming the forwarded call it acts under:
//!
//! ```json
//! ← {"jsonrpc":"2.0","id":1,"method":"_host.call","params":{"method":"weather.forecast","params":{"city":"lisbon"},"under":"3e1e8fa8-…"}}
//! → {"jsonrpc":"2.0","id":1,"result":1}
//! → {"jsonrpc":"2.0","method":"_host.call","params":{"subscription":1,"result":{"type":"data",…}}}
//! → {"jsonrpc":"2.0","method":"_host.call","params":{"subscription":1,"result":{"type":"done",…}}}
//! ← {"jsonrpc":"2.0","id":2,"method":"_host.call_unsub","params":[1]}
//! ```
//!
//! `under` is the forwarded call's `hop.call`. The service routes the call
//! through its own routing and gate — [`DynamicHub::route_with_ctx`], as
//! any caller's — **as that call's caller** (`hop.for`'s far end, the
//! identity its own gate admitted), **within that call's reach**: one more
//! ceiling layer, `admin@<scope>` for each scope the forwarded call was
//! admitted on (BIDIR-5's `hop_identity` rule: the far side only ever
//! narrows). A call refused by the gate is the subscription id, then one
//! `error` item (as `{ns}.call` answers it). When the forwarded call ends
//! (its last item, its caller letting go, the connection going) or its grant
//! is revoked (the grants generation moves and its reach is held nowhere),
//! every call made under it ends with one `error` item. A call naming no
//! live forwarded call is refused at the JSON-RPC layer, `unauthenticated`,
//! naming why — with one exception: outside any call a child may ask its
//! service for a **schema** (`<path>.schema`), answered from the service's
//! whole description, so it can learn, at its start, the shape of what it
//! will call.
//!
//! [`DynamicHub::route_with_ctx`]: crate::plexus::DynamicHub::route_with_ctx

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use plexus_auth_core::grants::{Reach, CEILING_KEY};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use super::link::meta;
use crate::plexus::auth::AuthContext;
use crate::plexus::service_scope::{self, WeakService};
use crate::plexus::types::PlexusStreamItem;
use crate::plexus::{parent, plexus_error_to_jsonrpc, PlexusError};

/// The method a child opens a call into its service with.
pub const HOST_CALL: &str = "_host.call";
/// The method a child lets go of such a call with (`[sid]`).
pub const HOST_CALL_UNSUB: &str = "_host.call_unsub";

/// One forwarded call open into the child: whom it acts for, within what,
/// and in which service.
pub(super) struct Under {
    auth: Option<AuthContext>,
    reach: Reach,
    service: WeakService,
    /// `Some(why)` once the forwarded call has ended.
    ended: watch::Sender<Option<String>>,
}

/// What a mount keeps for its child's calls back: the service it is in and
/// the forwarded calls open now, by their hop's `call` id.
pub(super) struct Upcalls {
    host: Mutex<Option<WeakService>>,
    under: Mutex<HashMap<String, Arc<Under>>>,
    /// Calls the child made back, in all.
    pub made: AtomicU64,
    /// NEST-16: the methods the child's schema says it needs (`None`: it
    /// declares none), set when it is mounted.
    needs: Mutex<Option<Arc<[String]>>>,
    /// NEST-16: NEST-11's broad rule for a child that declares no needs —
    /// anything its caller could reach ([`ChildOptions::legacy_upcalls`]).
    ///
    /// [`ChildOptions::legacy_upcalls`]: super::ChildOptions::legacy_upcalls
    legacy: bool,
}

impl Upcalls {
    pub(super) fn new(host: Option<WeakService>, legacy: bool) -> Arc<Self> {
        Arc::new(Self { host: Mutex::new(host), under: Mutex::default(), made: AtomicU64::new(0), needs: Mutex::default(), legacy })
    }

    /// NEST-16: what the mounted child's schema says it needs.
    pub(super) fn set_needs(&self, needs: Option<&[crate::plexus::schema::Need]>) {
        *self.needs.lock().unwrap() = needs.map(|n| n.iter().map(|n| n.method.clone()).collect::<Vec<_>>().into());
    }

    /// NEST-16: may the child call `method` up — the standard interface, a
    /// need, or anything under the legacy rule for a child that declares
    /// none. `Some(true)` when it is a need (routed under its own grant).
    fn allows(&self, method: &str) -> Option<bool> {
        if parent::is_standard(method) {
            return Some(false);
        }
        match self.needs.lock().unwrap().as_ref() {
            Some(needs) if needs.iter().any(|n| n == method) => Some(true),
            Some(_) => None,
            None if self.legacy => Some(false),
            None => None,
        }
    }

    /// The service the child is in: the one given, else the one a call was
    /// routed in when it was first seen.
    fn host(&self) -> Option<WeakService> {
        let mut h = self.host.lock().unwrap();
        if h.as_ref().and_then(WeakService::upgrade).is_none() {
            if let Some(now) = service_scope::current() {
                *h = Some(now);
            }
        }
        h.clone()
    }

    /// A forwarded call opens: the child may call back under `id` until the
    /// guard is dropped (or [`UnderGuard::end`]ed).
    pub(super) fn open(self: &Arc<Self>, id: &str, auth: Option<&AuthContext>, reach: &Reach) -> Option<UnderGuard> {
        let service = service_scope::current().or_else(|| self.host())?;
        let (ended, _) = watch::channel(None);
        let under = Arc::new(Under { auth: auth.cloned(), reach: reach.clone(), service, ended });
        self.under.lock().unwrap().insert(id.to_string(), Arc::clone(&under));
        Some(UnderGuard { up: Arc::clone(self), id: id.to_string(), under })
    }

    /// How many forwarded calls the child may call back under now.
    pub(super) fn open_now(&self) -> usize {
        self.under.lock().unwrap().len()
    }
}

/// A forwarded call's standing for the child's calls back: dropped, the
/// calls made under it end.
pub(super) struct UnderGuard {
    up: Arc<Upcalls>,
    id: String,
    under: Arc<Under>,
}

impl UnderGuard {
    /// The forwarded call has ended, and why.
    pub(super) fn end(&self, why: &str) {
        self.up.under.lock().unwrap().remove(&self.id);
        self.under.ended.send_if_modified(|e| {
            if e.is_none() {
                *e = Some(why.to_string());
                true
            } else {
                false
            }
        });
    }
}

impl Drop for UnderGuard {
    fn drop(&mut self) {
        self.end("it ended");
    }
}

/// `auth`, its reach narrowed to `reach`'s scopes: one more ceiling layer,
/// `admin@<scope>` each (any grant, only there) — none when `reach` holds
/// everywhere. NEST-16 (TM-1): for a need, the layer is its own grant on
/// each of those scopes (`shop.items@*` when everywhere), so the call back
/// reaches that method and nothing else, whatever the caller holds.
fn narrowed(auth: &AuthContext, reach: &Reach, grant: Option<&str>) -> AuthContext {
    if reach.is_everywhere() && grant.is_none() {
        return auth.clone();
    }
    let mut ctx = auth.clone();
    let mut layers: Vec<Value> = match ctx.metadata.get(CEILING_KEY) {
        Some(Value::Array(items)) if items.iter().all(Value::is_string) => vec![Value::Array(items.clone())],
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
        None => Vec::new(),
    };
    let what = grant.unwrap_or(plexus_auth_core::grants::ADMIN);
    let scopes: Vec<String> = if reach.is_everywhere() { vec!["*".into()] } else { reach.held_on().iter().map(|s| s.to_string()).collect() };
    layers.push(Value::Array(scopes.iter().map(|s| json!(format!("{what}@{s}"))).collect()));
    if !ctx.metadata.is_object() {
        ctx.metadata = json!({});
    }
    ctx.metadata[CEILING_KEY] = Value::Array(layers);
    ctx
}

/// A refusal at the JSON-RPC layer, typed.
fn refusal(id: &Value, e: &PlexusError) -> Value {
    let mut error = serde_json::to_value(plexus_error_to_jsonrpc(e)).unwrap_or_default();
    // The reason in words, as the error item says it (the typed `data`
    // carries the kind).
    error["message"] = json!(e.to_string());
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

/// The calls a connection serves its child, by the subscription id this
/// side minted.
#[derive(Default)]
pub(super) struct Served {
    next: AtomicU64,
    open: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
}

impl Served {
    /// The connection went: every call it served ends.
    pub(super) fn abort_all(&self) {
        for (_, h) in self.open.lock().unwrap().drain() {
            h.abort();
        }
    }
}

/// A request from the child: `_host.call` (opens) or `_host.call_unsub`
/// (lets go). `out` is the connection's writer.
pub(super) fn on_request(up: &Arc<Upcalls>, served: &Arc<Served>, out: &mpsc::UnboundedSender<Vec<u8>>, name: &str, id: Value, method: &str, params: Value) {
    let send = |v: Value| {
        let _ = out.send(serde_json::to_vec(&v).unwrap_or_default());
    };
    if method == HOST_CALL_UNSUB {
        let held = params.get(0).and_then(Value::as_u64).and_then(|sid| served.open.lock().unwrap().remove(&sid));
        let stopped = held.map(|h| h.abort()).is_some();
        return send(json!({ "jsonrpc": "2.0", "id": id, "result": stopped }));
    }
    let Some(mut target) = params.get("method").and_then(Value::as_str).map(str::to_string) else {
        return send(refusal(&id, &PlexusError::invalid_params("`_host.call` names the `method` it calls")));
    };
    let args = params.get("params").cloned().unwrap_or_else(|| json!({}));
    let under_id = params.get("under").and_then(Value::as_str).map(str::to_string);
    // NEST-16: the standard upward interface, the child's needs, or (a
    // child that declares none, under the legacy option) NEST-11's rule.
    let Some(need) = up.allows(&target) else {
        return send(refusal(&id, &parent::not_needed(&target)));
    };
    let standard = matches!(target.as_str(), parent::HOST_WHOAMI | parent::HOST_LOG | parent::HOST_NOTIFY);
    if target == parent::HOST_SCHEMA {
        if let Some(svc) = up.host().and_then(|h| h.upgrade()) {
            target = format!("{}.schema", svc.runtime_namespace());
        }
    }
    let route = match &under_id {
        Some(u) => match up.under.lock().unwrap().get(u) {
            Some(under) if standard => Route::Standard(under.service.clone(), under.auth.clone()),
            Some(under) => Route::Under(Arc::clone(under), need),
            None => {
                return send(refusal(&id, &PlexusError::Unauthenticated(format!(
                    "no call `{u}` is open into this child: a child calls its service only under a call it is serving, while it is open"
                ))))
            }
        },
        None => {
            let schema = target.ends_with(".schema");
            match (schema || standard, up.host()) {
                (true, Some(host)) if standard => Route::Standard(host, None),
                (true, Some(host)) => Route::Schema(host),
                (true, None) => {
                    return send(refusal(&id, &PlexusError::Unauthenticated(
                        "this child's service is not known yet: it is learned with the first call forwarded to it".into(),
                    )))
                }
                (false, _) => {
                    return send(refusal(&id, &PlexusError::Unauthenticated(format!(
                        "`{target}` names no call it acts under (`under`): a child calls its service only under a call it is serving; outside one it may ask only for a schema, or call `host.log` and `host.notify`"
                    ))))
                }
            }
        }
    };
    up.made.fetch_add(1, Ordering::Relaxed);
    let sid = served.next.fetch_add(1, Ordering::Relaxed) + 1;
    // spec/02: the subscription id before any of its items.
    send(json!({ "jsonrpc": "2.0", "id": id, "result": sid }));
    let (out, served2, name) = (out.clone(), Arc::clone(served), name.to_string());
    // Registered before it can end, so its end always finds it.
    let mut open = served.open.lock().unwrap();
    let task = tokio::spawn(async move {
        pump(route, &out, sid, &name, &target, args).await;
        served2.open.lock().unwrap().remove(&sid);
    });
    open.insert(sid, task.abort_handle());
}

enum Route {
    /// A call under a forwarded call; `true`: one of the child's needs.
    Under(Arc<Under>, bool),
    Schema(WeakService),
    /// NEST-16: `host.whoami`, `host.log` or `host.notify`, answered by the
    /// service itself, for the caller of the call it is made under.
    Standard(WeakService, Option<AuthContext>),
}

/// One call the child made: routed, its items written back under `sid`
/// until the last — or until the call it was made under ends.
async fn pump(route: Route, out: &mpsc::UnboundedSender<Vec<u8>>, sid: u64, name: &str, target: &str, args: Value) {
    let item = |i: &PlexusStreamItem| {
        let frame = json!({ "jsonrpc": "2.0", "method": HOST_CALL, "params": { "subscription": sid, "result": i } });
        let _ = out.send(serde_json::to_vec(&frame).unwrap_or_default());
    };
    let gone = || PlexusStreamItem::error(meta(name), plexus_client::RemoteError::Unauthenticated, false);
    let ended_item = |why: &str| {
        let mut e = gone();
        if let PlexusStreamItem::Error { message, .. } = &mut e {
            *message = format!("the call this was made under has ended ({why})");
        }
        e
    };
    let (under, service) = match &route {
        Route::Under(u, _) => (Some(Arc::clone(u)), u.service.upgrade()),
        Route::Schema(s) | Route::Standard(s, _) => (None, s.upgrade()),
    };
    let Some(service) = service else {
        let mut e = gone();
        if let PlexusStreamItem::Error { message, .. } = &mut e {
            *message = "the service this child is mounted in has gone".into();
        }
        return item(&e);
    };
    if let Route::Standard(_, caller) = &route {
        for i in parent::standard_answer(&service, name, target, &args, caller.as_ref()).unwrap_or_default() {
            item(&i);
        }
        return;
    }
    let need = matches!(route, Route::Under(_, true));
    let routed = match &under {
        Some(u) => {
            // TM-1: a need is routed under its own grant as one more ceiling.
            let grant = if need { service.grant_at(target) } else { None };
            let auth = u.auth.as_ref().map(|a| narrowed(a, &u.reach, grant.as_deref()));
            service.route_with_ctx(target, args, auth.as_ref(), None).await
        }
        None => service.schema_for_child(target, args).await,
    };
    let mut stream = match routed {
        Ok(s) => s,
        Err(e) => {
            let v = crate::plexus::error_item(service.runtime_namespace(), &e);
            let frame = json!({ "jsonrpc": "2.0", "method": HOST_CALL, "params": { "subscription": sid, "result": v } });
            let _ = out.send(serde_json::to_vec(&frame).unwrap_or_default());
            return;
        }
    };
    let Some(under) = under else {
        while let Some(i) = stream.next().await {
            item(&i);
        }
        return;
    };
    let mut ended = under.ended.subscribe();
    if let Some(why) = ended.borrow().clone() {
        return item(&ended_item(&why));
    }
    // The forwarded call's grant, asked again when the grants move.
    let mut moved = under.reach.generation().map(|g| g.subscribe());
    loop {
        tokio::select! {
            next = stream.next() => match next {
                Some(i) => {
                    let terminal = matches!(i, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. });
                    item(&i);
                    if terminal {
                        return;
                    }
                }
                None => return,
            },
            _ = ended.changed() => {
                let why = ended.borrow().clone().unwrap_or_default();
                return item(&ended_item(&why));
            }
            changed = async { match moved.as_mut() { Some(m) => m.changed().await, None => std::future::pending().await } } => {
                if changed.is_err() {
                    moved = None;
                } else if under.reach.current().is_none() {
                    return item(&ended_item("its grant was revoked"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef};

    /// The narrowed caller holds what it held, only where the call reached.
    #[test]
    fn a_call_back_is_narrowed_to_the_forwarded_calls_scopes() {
        struct Held;
        impl Memberships for Held {
            fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
                vec![Membership { principal: who.clone(), role: plexus_auth_core::RoleName::new("viewer"), scope: ScopeRef::Everywhere }]
            }
        }
        struct Chain;
        impl Resolve for Chain {
            fn chain(&self, t: &str) -> Option<Vec<ScopeRef>> {
                Some(vec![ScopeRef::named(t), ScopeRef::Everywhere])
            }
        }
        let roles = RoleTable::from_lists([("viewer", ["a.get", "b.get"])]);
        let gate = Gate::new(Arc::new(Held), Arc::new(roles), Arc::new(Chain));
        let who = AuthContext::for_principal(&"key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap(), "s", vec![], Value::Null);
        let wide = gate.check(Some(&who), &plexus_auth_core::grants::Grant::new("a.get"), None).unwrap();
        assert_eq!(narrowed(&who, &wide, None).metadata, who.metadata, "held everywhere: nothing added");
        // A reach held on `X` alone: the call back reaches `b.get` on X, not on Y.
        let mut n = who.clone();
        n.metadata[CEILING_KEY] = json!([["admin@X"]]);
        let narrow = n.clone();
        let g = plexus_auth_core::grants::Grant::new("b.get");
        assert!(gate.check(Some(&narrow), &g, Some("X")).is_ok());
        assert!(gate.check(Some(&narrow), &g, Some("Y")).is_err());
        let layered = narrowed(&n, &gate.check(Some(&n), &plexus_auth_core::grants::Grant::new("a.get"), None).unwrap(), None);
        assert_eq!(layered.metadata[CEILING_KEY].as_array().unwrap().len(), 2, "{:?}", layered.metadata);
        assert!(gate.check(Some(&layered), &g, Some("Y")).is_err());
    }
}
