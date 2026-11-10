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

/// DYNAUTH-5: one of a child's needs an admin consented to, and where:
/// `scopes` `["*"]` anywhere its caller reaches, else only on those.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Consented {
    /// The need, by its path from the service (`shop.items`).
    pub method: String,
    /// The scopes it may be called on (`["*"]`, `["MENGER"]`).
    pub scopes: Vec<String>,
}

/// One forwarded call open into the child: whom it acts for, within what,
/// and in which service.
pub(super) struct Under {
    auth: Option<AuthContext>,
    reach: Reach,
    service: WeakService,
    /// `Some(why)` once the forwarded call has ended.
    ended: watch::Sender<Option<String>>,
    /// DYNAUTH-12: the token minted for the forwarded call, if one was.
    minted: Option<Minted>,
}

tokio::task_local! {
    /// DYNAUTH-6: the token a call back is made under, while it is routed.
    static PRESENTED: crate::plexus::peer_token::PeerClaims;
}

/// DYNAUTH-6: the token a call back was made under, while that call back
/// is routed — so a call it reaches into another child is an exchange
/// (RFC 8693: the same `sub`, the presenter in `act`, a scope never wider),
/// not a fresh mint.
pub(super) fn presented() -> Option<crate::plexus::peer_token::PeerClaims> {
    PRESENTED.try_with(Clone::clone).ok()
}

/// DYNAUTH-12: a token minted for one forwarded call, and what it says.
#[derive(Clone)]
pub(super) struct Minted {
    pub token: String,
    pub claims: crate::plexus::peer_token::PeerClaims,
}

/// What a mount keeps for its child's calls back: the service it is in and
/// the forwarded calls open now, by their hop's `call` id.
pub(super) struct Upcalls {
    host: Mutex<Option<WeakService>>,
    under: Mutex<HashMap<String, Arc<Under>>>,
    /// Calls the child made back, in all.
    pub made: AtomicU64,
    /// DYNAUTH-12: the proofs of possession seen, each once.
    proofs: crate::plexus::peer_token::ProofCache,
    /// NEST-16: the methods the child's schema says it needs (`None`: it
    /// declares none), set when it is mounted.
    needs: Mutex<Option<Arc<[String]>>>,
    /// DYNAUTH-5: what an admin consented to of those needs, each on the
    /// scopes it may be called on (`None`: no consent is kept for this
    /// mount — a declared need is enough, as NEST-16 has it).
    consent: Mutex<Option<Arc<[Consented]>>>,
    /// NEST-16: NEST-11's broad rule for a child that declares no needs —
    /// anything its caller could reach ([`ChildOptions::legacy_upcalls`]).
    ///
    /// [`ChildOptions::legacy_upcalls`]: super::ChildOptions::legacy_upcalls
    legacy: bool,
    /// DYNAUTH-7: revoked, and why: no call is forwarded, no token minted,
    /// and (KEEL-19) nothing is decided for it — no call back, no exchange.
    revoked: Mutex<Option<String>>,
    /// KEEL-32: the paths whose schemas it may read outside any call before
    /// its needs are known ([`super::ChildOptions::schemas`]).
    schemas: Mutex<Arc<[String]>>,
}

/// KEEL-19: what [`Upcalls::decide`] answers for a need: the scopes it is
/// consented on now (`["*"]` anywhere), and, decided under a token, the
/// scopes both that token holds its grant on and the consent holds now
/// (KEEL-20's first row: a consent narrowed while a call is open narrows
/// the next call back made under it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Decided {
    pub consented: Vec<String>,
    pub held: Option<Vec<String>>,
}

impl Upcalls {
    pub(super) fn new(host: Option<WeakService>, legacy: bool) -> Arc<Self> {
        Arc::new(Self { host: Mutex::new(host), under: Mutex::default(), made: AtomicU64::new(0), proofs: Default::default(), needs: Mutex::default(), consent: Mutex::default(), legacy, revoked: Mutex::default(), schemas: Mutex::new(Arc::from(Vec::new())) })
    }

    /// KEEL-32: see [`super::ChildOptions::schemas`].
    pub(super) fn set_schemas(&self, paths: &[String]) {
        *self.schemas.lock().unwrap() = paths.to_vec().into();
    }

    /// KEEL-32 · a schema the child asks for **outside any call**, answered
    /// as the child — never as the service with everything, or anyone's
    /// view but its own. `path` is the bare path (`weather.weather`,
    /// `dyn.peer.w`), `crosses_slot` whether reaching it looks a name up in
    /// a dynamic or peer slot. Answered when it is:
    ///
    /// - at or above one of its needs, declared and consented
    ///   ([`Upcalls::decide`]'s rule): the shape of what it may call;
    /// - at, above or below a path it was mounted to read
    ///   ([`super::ChildOptions::schemas`]) — what it grows from at its
    ///   start, before its needs are known;
    /// - for a child under the legacy rule that declares no needs, a
    ///   static path (no slot lookup on its way), as NEST-11 had it.
    ///
    /// A revoked child is answered nothing; anything else is not found —
    /// never routed, so no dynamic child or peer is looked up for it.
    pub(super) fn may_read_schema(&self, path: &str, crosses_slot: bool) -> Result<(), (PlexusError, String)> {
        if let Some(why) = self.revoked() {
            return Err((PlexusError::Unauthenticated(format!("this child is revoked ({why})")), format!("this child is revoked ({why}): it is answered no schema")));
        }
        let at_or_above = |n: &str| n == path || n.starts_with(&format!("{path}."));
        let at_above_or_below = |s: &str| at_or_above(s) || path.starts_with(&format!("{s}."));
        if self.schemas.lock().unwrap().iter().any(|s| at_above_or_below(s)) {
            return Ok(());
        }
        let needs = self.needs.lock().unwrap().clone();
        if let Some(needs) = &needs {
            let consent = self.consent.lock().unwrap().clone();
            let consented = |n: &String| consent.as_ref().is_none_or(|c| c.iter().any(|c| &c.method == n));
            if needs.iter().filter(|n| consented(n)).any(|n| at_or_above(n)) {
                return Ok(());
            }
        } else if self.legacy && !crosses_slot {
            return Ok(());
        }
        let (ns, rest) = path.split_once('.').unwrap_or((path, ""));
        let e = if rest.is_empty() {
            PlexusError::ActivationNotFound(ns.to_string())
        } else {
            PlexusError::MethodNotFound { activation: ns.to_string(), method: rest.to_string() }
        };
        let said = format!("`{path}.schema` is not among what this child needs or was mounted to read: not found");
        Err((e, said))
    }

    /// NEST-16: what the mounted child's schema says it needs.
    pub(super) fn set_needs(&self, needs: Option<&[crate::plexus::schema::Need]>) {
        *self.needs.lock().unwrap() = needs.map(|n| n.iter().map(|n| n.method.clone()).collect::<Vec<_>>().into());
    }

    /// DYNAUTH-5: what an admin consented to (`None`: no consent kept).
    pub(super) fn set_consent(&self, consent: Option<Vec<Consented>>) {
        *self.consent.lock().unwrap() = consent.map(Into::into);
    }

    /// DYNAUTH-5: the consent kept now.
    pub(super) fn consent(&self) -> Option<Arc<[Consented]>> {
        self.consent.lock().unwrap().clone()
    }

    /// DYNAUTH-7: revoke: no call back is decided from now, and every one
    /// open ends saying why.
    pub(super) fn revoke(&self, why: &str) {
        *self.revoked.lock().unwrap() = Some(why.to_string());
        self.end_all(&format!("revoked: {why}"));
    }

    /// DYNAUTH-7: why the child is revoked, if it is.
    pub(super) fn revoked(&self) -> Option<String> {
        self.revoked.lock().unwrap().clone()
    }

    /// KEEL-19 · **the one decision** of what this child may reach of its
    /// service — a call back's ([`on_request`]) and an exchange's
    /// ([`super::RemoteChild::may_exchange`]) alike: the standard interface
    /// (`Ok(None)`), or a need — declared, consented, and the child not
    /// revoked — and, under `token` (the token its call was made under, and
    /// the service that names the need's grant), only where that token holds
    /// the need's grant. `Err` the refusal, typed and said.
    pub(super) fn decide(&self, method: &str, token: Option<(&crate::plexus::DynamicHub, &crate::plexus::peer_token::PeerClaims)>) -> Result<Option<Decided>, (PlexusError, String)> {
        if parent::is_standard(method) {
            return Ok(None);
        }
        if let Some(why) = self.revoked() {
            return Err((PlexusError::Unauthenticated(format!("this child is revoked ({why})")), format!("this child is revoked ({why}): nothing it asks is decided for it")));
        }
        let Some(consented) = self.allows(method)? else { return Ok(None) };
        let held = match token {
            None => None,
            Some((svc, claims)) => {
                let held = svc.grant_at(method).map(|g| claims.scopes_for(&g)).unwrap_or_default();
                if held.is_empty() {
                    let e = parent::not_needed(method);
                    return Err((e, format!("`{method}` is not within the scope of the token minted for this call")));
                }
                let both = intersect(&held, &consented);
                if both.is_empty() {
                    let e = parent::not_needed(method);
                    return Err((e, format!("`{method}` is consented on {consented:?} now, and the token holds it on {held:?}: nowhere both")));
                }
                Some(both)
            }
        };
        Ok(Some(Decided { consented, held }))
    }

    /// NEST-16: may the child call `method` up — the standard interface, a
    /// need, or anything under the legacy rule for a child that declares
    /// none. DYNAUTH-5: a need must also be consented, when consent is
    /// kept. `Ok(Some(scopes))` for a need (routed under its own grant,
    /// only on `scopes` — `["*"]` anywhere), `Ok(None)` for the rest;
    /// `Err` the refusal, said.
    fn allows(&self, method: &str) -> Result<Option<Vec<String>>, (PlexusError, String)> {
        if parent::is_standard(method) {
            return Ok(None);
        }
        let declared = match self.needs.lock().unwrap().as_ref() {
            Some(needs) => needs.iter().any(|n| n == method),
            None if self.legacy => return Ok(None),
            None => false,
        };
        if !declared {
            let e = parent::not_needed(method);
            let said = e.to_string();
            return Err((e, said));
        }
        match self.consent.lock().unwrap().as_ref() {
            None => Ok(Some(vec!["*".into()])),
            Some(c) => match c.iter().find(|c| c.method == method) {
                Some(c) => Ok(Some(c.scopes.clone())),
                None => Err((
                    parent::not_needed(method),
                    format!("`{method}` is among this child's needs, but no admin has consented to it (dyn.consent): a declared need is a request, not a grant"),
                )),
            },
        }
    }

    /// The service the child is in: the one given, else the one a call was
    /// routed in when it was first seen.
    pub(super) fn host(&self) -> Option<WeakService> {
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
    pub(super) fn open(self: &Arc<Self>, id: &str, auth: Option<&AuthContext>, reach: &Reach, minted: Option<Minted>) -> Option<UnderGuard> {
        // The service is learned here, with the first call forwarded (a
        // schema the child asks outside any call is answered by it).
        let known = self.host();
        let service = service_scope::current().or(known)?;
        let (ended, _) = watch::channel(None);
        let under = Arc::new(Under { auth: auth.cloned(), reach: reach.clone(), service, ended, minted });
        {
            // KEEL-19: a revoked child is opened nothing to call back under —
            // asked under the lock `revoke`'s `end_all` drains, after the
            // mark is set, so an open either sees the mark or is drained.
            let mut open = self.under.lock().unwrap();
            if self.revoked().is_some() {
                return None;
            }
            open.insert(id.to_string(), Arc::clone(&under));
        }
        Some(UnderGuard { up: Arc::clone(self), id: id.to_string(), under })
    }

    /// DYNAUTH-12: the needs a token minted now may hold, each by the grant
    /// the service holds a call to it to and the scopes it is consented on
    /// (`["*"]` without consent kept).
    pub(super) fn need_grants(&self, service: &crate::plexus::DynamicHub) -> Vec<(String, Vec<String>)> {
        let needs = self.needs.lock().unwrap().clone().unwrap_or_else(|| Vec::<String>::new().into());
        let consent = self.consent.lock().unwrap().clone();
        needs
            .iter()
            .filter_map(|m| {
                let scopes = match &consent {
                    None => vec!["*".to_string()],
                    Some(c) => c.iter().find(|c| &c.method == m)?.scopes.clone(),
                };
                Some((service.grant_at(m)?, scopes))
            })
            .collect()
    }

    /// DYNAUTH-7: every forwarded call open now ends for the child's calls
    /// back — each made under one ends with one error item, saying `why`.
    pub(super) fn end_all(&self, why: &str) {
        let open: Vec<Arc<Under>> = self.under.lock().unwrap().drain().map(|(_, u)| u).collect();
        for u in open {
            u.ended.send_if_modified(|e| {
                if e.is_none() {
                    *e = Some(why.to_string());
                    true
                } else {
                    false
                }
            });
        }
    }

    /// How many forwarded calls the child may call back under now.
    pub(super) fn open_now(&self) -> usize {
        self.under.lock().unwrap().len()
    }
}

/// Each scope both `a` and `b` hold, the narrower of each pair (`*` holds
/// every scope).
fn intersect(a: &[String], b: &[String]) -> Vec<String> {
    let within = |inner: &str, outer: &str| outer == "*" || inner == outer;
    let mut out: Vec<String> = Vec::new();
    for x in a {
        for y in b {
            let s = if within(x, y) {
                x
            } else if within(y, x) {
                y
            } else {
                continue;
            };
            if !out.contains(s) {
                out.push(s.clone());
            }
        }
    }
    out
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
/// `admin@<scope>` each — none when `reach` holds everywhere. DYNAUTH-6:
/// `admin@X` in a ceiling layer is not the admin role: it reads "any grant,
/// only on X" (the gate's `admin` lists every grant), so it narrows by
/// *where* only — the outer bound, kept for a child under the legacy rule.
/// What a child may *do* is the need's own grant (below) and its token's
/// scope. NEST-16 (TM-1): for a need, the layer is its own grant on
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

/// DYNAUTH-12: the token and proof a keyed child presents with a call
/// back, checked against the token minted for the call it names.
fn presented_ok(up: &Upcalls, m: &Minted, params: &Value, method: &str, under: &str) -> Result<(), String> {
    if let Some(t) = params.get("token").and_then(Value::as_str) {
        if t != m.token {
            return Err("the token presented is not the one minted for this call".into());
        }
    }
    if m.claims.cnf.is_none() {
        return Ok(());
    }
    let proof = params.get("proof").and_then(Value::as_str).ok_or_else(|| {
        "a call back under a key-bound token carries a proof of possession (`proof`): none was sent".to_string()
    })?;
    crate::plexus::peer_token::check_proof(proof, &m.token, &m.claims, method, under, crate::plexus::peer_token::now(), &up.proofs)
        .map_err(|e| format!("the call back's {e}"))
}

/// DYNAUTH-5: `auth` with one more ceiling layer, `grant@<scope>` for each
/// consented scope — a need consented on `MENGER` reaches only there.
fn consented(auth: &AuthContext, grant: &str, scopes: &[String]) -> AuthContext {
    let mut ctx = auth.clone();
    let mut layers: Vec<Value> = match ctx.metadata.get(CEILING_KEY) {
        Some(Value::Array(items)) if items.iter().all(Value::is_string) => vec![Value::Array(items.clone())],
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
        None => Vec::new(),
    };
    layers.push(Value::Array(scopes.iter().map(|s| json!(format!("{grant}@{s}"))).collect()));
    if !ctx.metadata.is_object() {
        ctx.metadata = json!({});
    }
    ctx.metadata[CEILING_KEY] = Value::Array(layers);
    ctx
}

/// A refusal at the JSON-RPC layer, typed, said in its own words.
fn refusal_said(id: &Value, e: &PlexusError, said: &str) -> Value {
    let mut r = refusal(id, e);
    r["error"]["message"] = json!(said);
    r
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
    // DYNAUTH-12: the method as the child asked it (what its proof names).
    let presented = target.clone();
    let under_id = params.get("under").and_then(Value::as_str).map(str::to_string);
    // NEST-16: the standard upward interface, the child's needs, or (a
    // child that declares none, under the legacy option) NEST-11's rule.
    // KEEL-19: decided by the one function an exchange is decided by.
    let need = match up.decide(&target, None) {
        Ok(need) => need.map(|d| d.consented),
        Err((e, said)) => return send(refusal_said(&id, &e, &said)),
    };
    let standard = matches!(target.as_str(), parent::HOST_WHOAMI | parent::HOST_LOG | parent::HOST_NOTIFY);
    if target == parent::HOST_SCHEMA {
        if let Some(svc) = up.host().and_then(|h| h.upgrade()) {
            target = format!("{}.schema", svc.runtime_namespace());
        }
    }
    let route = match &under_id {
        Some(u) => match up.under.lock().unwrap().get(u).cloned() {
            Some(under) => {
                // DYNAUTH-12: under a call whose token is bound to the
                // child's key, every call back carries a proof of
                // possession by that key, for this method and call (a
                // child on the service's own pipe needs none, D3).
                if let Some(m) = &under.minted {
                    if let Err(e) = presented_ok(up, m, &params, &presented, u) {
                        return send(refusal_said(&id, &PlexusError::Unauthenticated(e.clone()), &e));
                    }
                }
                if standard {
                    Route::Standard(under.service.clone(), under.auth.clone())
                } else {
                    // DYNAUTH-12: a need is held to the token's scope too.
                    let need = match (&under.minted, need, under.service.upgrade()) {
                        (Some(m), Some(_), Some(svc)) => match up.decide(&target, Some((&svc, &m.claims))) {
                            Ok(d) => d.and_then(|d| d.held),
                            Err((e, said)) => return send(refusal_said(&id, &e, &said)),
                        },
                        (_, n, _) => n,
                    };
                    Route::Under(under, need)
                }
            }
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
                (true, Some(host)) => {
                    // KEEL-32: answered as the child — its needs, what it
                    // was mounted to read — or not found, never routed.
                    if let Some(svc) = host.upgrade() {
                        let own = format!("{}.schema", svc.runtime_namespace());
                        if target == own {
                            if let Some(why) = up.revoked() {
                                let e = PlexusError::Unauthenticated(format!("this child is revoked ({why})"));
                                return send(refusal(&id, &e));
                            }
                        } else {
                            let path = svc.bare_schema_path(&target);
                            if let Err((e, said)) = up.may_read_schema(&path, svc.crosses_slot(&path)) {
                                return send(refusal_said(&id, &e, &said));
                            }
                        }
                    }
                    Route::Schema(host)
                }
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
    /// A call under a forwarded call; `Some(scopes)`: one of the child's
    /// needs, consented on those scopes (DYNAUTH-5).
    Under(Arc<Under>, Option<Vec<String>>),
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
    let need = match &route {
        Route::Under(_, n) => n.clone(),
        _ => None,
    };
    let routed = match &under {
        Some(u) => {
            // TM-1: a need is routed under its own grant as one more ceiling;
            // DYNAUTH-5: and only on the scopes it was consented on.
            let grant = need.as_ref().and_then(|_| service.grant_at(target));
            let auth = u.auth.as_ref().map(|a| narrowed(a, &u.reach, grant.as_deref()));
            let auth = match (auth, &grant, &need) {
                (Some(a), Some(g), Some(scopes)) if !scopes.iter().any(|s| s == "*") => Some(consented(&a, g, scopes)),
                (a, _, _) => a,
            };
            // DYNAUTH-6: a call it reaches into another child is minted as
            // an exchange of the token this call back was made under.
            match &u.minted {
                Some(m) => PRESENTED.scope(m.claims.clone(), service.route_with_ctx(target, args, auth.as_ref(), None)).await,
                None => service.route_with_ctx(target, args, auth.as_ref(), None).await,
            }
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

    /// DYNAUTH-5: a declared need is called only once consented, and only
    /// on its consented scopes; without consent kept, NEST-16's rule.
    #[test]
    fn a_need_is_held_to_its_consent() {
        let up = Upcalls::new(None, false);
        let need = |m: &str| crate::plexus::schema::Need { method: m.into(), hash: String::new() };
        up.set_needs(Some(&[need("shop.items"), need("shop.orders")]));
        assert_eq!(up.allows("shop.items").unwrap(), Some(vec!["*".to_string()]), "no consent kept: declared is enough");
        assert!(up.allows("shop.secret").is_err(), "undeclared");
        assert_eq!(up.allows(parent::HOST_WHOAMI).unwrap(), None, "the standard four need nothing");
        up.set_consent(Some(vec![Consented { method: "shop.items".into(), scopes: vec!["MENGER".into()] }]));
        assert_eq!(up.allows("shop.items").unwrap(), Some(vec!["MENGER".to_string()]));
        let (e, said) = up.allows("shop.orders").unwrap_err();
        assert!(said.contains("consented"), "{said}");
        assert!(e.to_string().contains("shop.orders"));
        up.set_consent(Some(vec![]));
        assert!(up.allows("shop.items").is_err(), "an empty consent: nothing upward");
        // The consented scope is one more ceiling layer.
        let who = AuthContext::for_principal(&"key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap(), "s", vec![], Value::Null);
        let c = consented(&who, "shop.items", &["MENGER".to_string()]);
        assert_eq!(c.metadata[CEILING_KEY], json!([["shop.items@MENGER"]]));
    }

    /// DYNAUTH-12: a keyed child's call back carries a proof by its key,
    /// for this method and call; a pipe child's needs none.
    #[test]
    fn a_call_back_under_a_bound_token_needs_its_proof() {
        use crate::plexus::peer_token::{prove, MintRequest, PeerKey, TokenIssuer};
        let (host, child, thief) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let req = |peer_key: Option<String>| MintRequest { sub: "key:x".into(), peer_key, name: "w".into(), scope: vec![], call: "u1".into(), method: "w.m".into(), presented: None };
        let (token, claims) = issuer.mint(req(Some(child.kid().into()))).unwrap();
        let m = Minted { token: token.clone(), claims };
        let up = Upcalls::new(None, false);
        let no_proof = presented_ok(&up, &m, &json!({}), "shop.items", "u1").unwrap_err();
        assert!(no_proof.contains("proof"), "{no_proof}");
        let good = json!({ "token": token, "proof": prove(&child, &token, "shop.items", "u1") });
        assert_eq!(presented_ok(&up, &m, &good, "shop.items", "u1"), Ok(()));
        assert!(presented_ok(&up, &m, &good, "shop.items", "u1").is_err(), "a proof is used once");
        let stolen = json!({ "proof": prove(&thief, &token, "shop.items", "u1") });
        assert!(presented_ok(&up, &m, &stolen, "shop.items", "u1").unwrap_err().contains("another key"));
        let other_method = json!({ "proof": prove(&child, &token, "shop.items", "u1") });
        assert!(presented_ok(&up, &m, &other_method, "auth.grant", "u1").is_err());
        let other_token = json!({ "token": "a.b.c", "proof": prove(&child, &token, "shop.items", "u1") });
        assert!(presented_ok(&up, &m, &other_token, "shop.items", "u1").unwrap_err().contains("not the one"));
        // A pipe's token: bound to no key, no proof asked.
        let (token, claims) = issuer.mint(req(None)).unwrap();
        assert_eq!(presented_ok(&up, &Minted { token, claims }, &json!({}), "shop.items", "u1"), Ok(()));
    }

    /// KEEL-19: the one decision — a need declared and consented is decided;
    /// once the child is revoked, nothing but the standard interface is.
    #[test]
    fn a_revoked_child_is_decided_nothing() {
        let up = Upcalls::new(None, false);
        let need = |m: &str| crate::plexus::schema::Need { method: m.into(), hash: String::new() };
        up.set_needs(Some(&[need("dyn.peer.b.forecast")]));
        up.set_consent(Some(vec![Consented { method: "dyn.peer.b.forecast".into(), scopes: vec!["*".into()] }]));
        assert_eq!(up.decide("dyn.peer.b.forecast", None).unwrap(), Some(Decided { consented: vec!["*".into()], held: None }));
        up.revoke("compromised");
        let (_, said) = up.decide("dyn.peer.b.forecast", None).unwrap_err();
        assert!(said.contains("revoked (compromised)"), "{said}");
        assert_eq!(up.decide(parent::HOST_WHOAMI, None).unwrap(), None, "the standard interface is not this ticket's");
    }

    /// KEEL-19 (KEEL-22's first row): once revoked, nothing is opened to call
    /// back under — whatever `forward` awaited before it asked.
    #[tokio::test]
    async fn a_revoked_child_is_opened_nothing() {
        let up = Upcalls::new(None, false);
        let svc = crate::plexus::DynamicHub::new("svc");
        let reach = plexus_auth_core::grants::Reach::everywhere();
        let open = |id: &'static str| crate::plexus::service_scope::scope(svc.downgrade(), { let up = Arc::clone(&up); let reach = reach.clone(); async move { up.open(id, None, &reach, None) } });
        assert!(open("c1").await.is_some());
        up.revoke("compromised");
        assert!(open("c2").await.is_none(), "opened after the revoke");
        assert_eq!(up.open_now(), 0);
    }

    /// DYNAUTH-7: a revoked child's calls back end, each saying why.
    #[tokio::test]
    async fn revoking_ends_every_call_back() {
        let up = Upcalls::new(None, false);
        let svc = crate::plexus::DynamicHub::new("svc");
        let reach = plexus_auth_core::grants::Reach::everywhere();
        let guard = crate::plexus::service_scope::scope(svc.downgrade(), async { up.open("c1", None, &reach, None) }).await.expect("opened");
        let mut ended = guard.under.ended.subscribe();
        assert_eq!(up.open_now(), 1);
        up.end_all("revoked: compromised");
        assert_eq!(up.open_now(), 0);
        ended.changed().await.unwrap();
        assert_eq!(ended.borrow().as_deref(), Some("revoked: compromised"));
    }
}
