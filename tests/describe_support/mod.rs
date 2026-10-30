//! PERF-15's test service: AUTH-4's (a tickets activation behind the auth
//! activation, shortcode scopes, the reference stores), with two counters —
//! the schemas its activations build, and the role lookups its gate makes —
//! so a test sees what an ask computed, not only what it answered.
//!
//! Shared by `describe_cache.rs` and `describe_golden.rs`.

#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_stream::stream;
use async_trait::async_trait;
use futures::stream::{Stream, StreamExt};
use plexus_auth_core::RoleName;
use plexus_core::plexus::schema::PluginSchema;
use plexus_auth_core::grants::{GrantsMove, Liveness};
use plexus_core::plexus::{
    Activation, AuthContext, AuthSetup, ChildRouter, Gate, GrantSet, MembershipStore, MemoryAuthBackend,
    MemoryMemberships, MemoryRoles, PlexusStream, PlexusStreamItem, Resolve, RoleStore, Roles, ScopeRef,
    SessionValidator, StoreError, CEILING_KEY,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// The activations
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TicketsActivation;

#[plexus_macros::activation(
    version = "0.5.0",
    description = "Plans as data",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl TicketsActivation {
    /// One ticket by id.
    #[plexus_macros::method(target = "id", description = "One ticket by id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// Tickets, from where the caller holds them.
    #[plexus_macros::method(description = "Tickets, filtered and paged")]
    async fn list(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "all".to_string(); }
    }

    /// Change a ticket's status.
    #[plexus_macros::method(target = "id", description = "Change a ticket's status")]
    async fn set_status(&self, id: String, status: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("{id} -> {status}"); }
    }

    /// Listed by no role: admin only.
    #[plexus_macros::method(target = "id", description = "Delete a ticket")]
    async fn delete(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }
}

/// A second activation, to mount after the first (PERF-15: a mount drops
/// what the cache kept).
#[derive(Clone)]
pub struct NotesActivation;

#[plexus_macros::activation(version = "0.1.0", description = "Notes", roles(viewer = ["read"]))]
impl NotesActivation {
    /// Read the notes.
    #[plexus_macros::method(description = "Read the notes")]
    async fn read(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "a note".to_string(); }
    }
}

/// An activation that counts every schema it builds — its `plugin_schema`,
/// and a routed `schema` / `<method>.schema` (the macro builds the schema
/// inside `call`). Everything else is the inner activation's.
#[derive(Clone)]
pub struct Counted<A> {
    pub inner: A,
    pub built: Arc<AtomicUsize>,
}

#[async_trait]
impl<A: Activation + Clone> Activation for Counted<A> {
    type Methods = A::Methods;

    fn namespace(&self) -> &str {
        self.inner.namespace()
    }
    fn version(&self) -> &str {
        self.inner.version()
    }
    fn description(&self) -> &str {
        self.inner.description()
    }
    fn long_description(&self) -> Option<&str> {
        self.inner.long_description()
    }
    fn methods(&self) -> Vec<&str> {
        self.inner.methods()
    }
    fn method_help(&self, method: &str) -> Option<String> {
        self.inner.method_help(method)
    }
    fn plugin_id(&self) -> uuid::Uuid {
        self.inner.plugin_id()
    }
    async fn call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&plexus_core::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        if method == "schema" || method.ends_with(".schema") {
            self.built.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.call(method, params, auth, raw_ctx).await
    }
    fn into_rpc_methods(self) -> jsonrpsee::Methods {
        self.inner.into_rpc_methods()
    }
    fn static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        self.inner.static_child_schemas()
    }
    fn plugin_schema(&self) -> PluginSchema {
        self.built.fetch_add(1, Ordering::SeqCst);
        self.inner.plugin_schema()
    }
}

#[async_trait]
impl<A: Activation + ChildRouter + Clone> ChildRouter for Counted<A> {
    fn router_namespace(&self) -> &str {
        self.inner.router_namespace()
    }
    async fn router_call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&AuthContext>,
        raw_ctx: Option<&plexus_core::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError> {
        Activation::call(self, method, params, auth, raw_ctx).await
    }
    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.inner.get_child(name).await
    }
}

/// The reference role store, counting every lookup the gate makes of it —
/// which is what building a caller's view asks (introspection itself is
/// admitted without one).
pub struct CountingRoles {
    pub inner: Arc<MemoryRoles>,
    pub asked: Arc<AtomicUsize>,
}

impl Roles for CountingRoles {
    fn grants(&self, role: &RoleName) -> Option<GrantSet> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.grants(role)
    }
    fn names(&self) -> Vec<RoleName> {
        self.inner.names()
    }
}

#[async_trait]
impl RoleStore for CountingRoles {
    async fn set(&self, role: &RoleName, grants: GrantSet) -> Result<(), StoreError> {
        self.inner.set(role, grants).await
    }
}

/// `CODE-n` → `[CODE-n, CODE, *]`; `CODE` → `[CODE, *]`.
pub struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return None;
        }
        let mut chain = Vec::new();
        if target.contains('-') {
            chain.push(ScopeRef::named(target));
        }
        chain.push(ScopeRef::named(code));
        chain.push(ScopeRef::Everywhere);
        Some(chain)
    }
}

// ---------------------------------------------------------------------------
// The worlds
// ---------------------------------------------------------------------------

pub const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const CAT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
pub const ROOT: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub const DAN: &str = "key:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// AUTH-11: the sessions that ended — a `Liveness` a test signs out by hand.
#[derive(Default)]
pub struct Ended(pub Mutex<HashSet<String>>);

impl Liveness for Ended {
    fn alive(&self, caller: &AuthContext) -> Result<(), String> {
        if self.0.lock().unwrap().contains(&caller.session_id) {
            Err("you have signed out: sign in again".into())
        } else {
            Ok(())
        }
    }
}

pub struct World {
    pub service: Arc<DynamicHub>,
    /// The auth activation's backend, in `auth_world` only.
    pub backend: Option<Arc<MemoryAuthBackend>>,
    pub memberships: Arc<MemoryMemberships>,
    pub roles: Arc<MemoryRoles>,
    pub ended: Arc<Ended>,
    /// Schemas the activations built.
    pub built: Arc<AtomicUsize>,
    /// Role lookups the gate made.
    pub asked: Arc<AtomicUsize>,
}

impl World {
    pub fn built(&self) -> usize {
        self.built.load(Ordering::SeqCst)
    }
    pub fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
    /// The counters back to 0.
    pub fn reset(&self) {
        self.built.store(0, Ordering::SeqCst);
        self.asked.store(0, Ordering::SeqCst);
    }
    pub fn gate(&self) -> Arc<Gate> {
        self.service.gate().expect("a gated service").clone()
    }
    /// What `auth.revoke` does: the membership gone, then the generation moved.
    pub async fn revoke(&self, principal: &str, scope: &str) {
        let gone = self.memberships.revoke(&principal.parse().unwrap(), None, &ScopeRef::parse(scope)).await.unwrap();
        assert!(!gone.is_empty(), "{principal} held something on {scope}");
        self.gate().moved(GrantsMove::Revoke);
    }
    /// What `auth.role_set` does: the role's grants replaced, then the generation moved.
    pub async fn role_set(&self, role: &str, grants: &[&str]) {
        self.roles.set(&RoleName::new(role), GrantSet::listed(grants.iter().copied())).await.unwrap();
        self.gate().moved(GrantsMove::RoleEdit);
    }
    /// What `auth.logout` does: the session ended, then the generation moved.
    pub fn sign_out(&self, who: &AuthContext) {
        self.ended.0.lock().unwrap().insert(who.session_id.clone());
        self.gate().moved(GrantsMove::SignOut);
    }
}

fn stores() -> (Arc<MemoryMemberships>, Arc<MemoryRoles>) {
    let memberships = Arc::new(
        MemoryMemberships::new()
            .with(ADA, "editor", "MENGER")
            .with(BOB, "editor", "MENGER")
            .with(CAT, "editor", "IDENTITY")
            .with(ROOT, "admin", "*"),
    );
    (memberships, Arc::new(MemoryRoles::default()))
}

/// The service before it is shared, one activation behind a gate of its own:
/// ADA and BOB editors on MENGER, CAT on IDENTITY, ROOT admin on `*`, DAN
/// nothing. `world()` is it, shared. Its answers are the same from one
/// service to the next, as any service's are (PERF-21: a service lists its
/// activations by namespace).
pub fn service() -> (DynamicHub, impl FnOnce(DynamicHub) -> World) {
    let (memberships, roles) = stores();
    let (built, asked, ended) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(Ended::default()));
    let counting = Arc::new(CountingRoles { inner: roles.clone(), asked: asked.clone() });
    let gate = Gate::new(memberships.clone(), counting, Arc::new(Shortcodes)).with_liveness(ended.clone());
    let service = DynamicHub::new("menger")
        .register(Counted { inner: TicketsActivation, built: built.clone() })
        .with_gate(Arc::new(gate))
        .with_resource_metadata("http://127.0.0.1:4456/.well-known/oauth-protected-resource");
    roles.seed(&service.declared_roles());
    let shared = move |service: DynamicHub| World { service: Arc::new(service), backend: None, memberships, roles, ended, built, asked };
    (service, shared)
}

pub fn world() -> World {
    let (unshared, shared) = service();
    shared(unshared)
}

/// AUTH-5's service: the auth activation mounted beside tickets, the
/// reference stores under it. Its two activations are listed by namespace,
/// `auth` before `tickets`, at every start (PERF-21, `describe_starts.rs`).
pub fn auth_world() -> World {
    let (memberships, roles) = stores();
    let backend = Arc::new(MemoryAuthBackend::new("http://127.0.0.1:4456/login"));
    let (built, asked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let counting = Arc::new(CountingRoles { inner: roles.clone(), asked: asked.clone() });
    let service = DynamicHub::new("menger")
        .register(Counted { inner: TicketsActivation, built: built.clone() })
        .with_auth(AuthSetup::new(backend.clone(), counting, memberships.clone(), Arc::new(Shortcodes)))
        .with_resource_metadata("http://127.0.0.1:4456/.well-known/oauth-protected-resource");
    roles.seed(&service.declared_roles());
    World { service: Arc::new(service), backend: Some(backend), memberships, roles, ended: Arc::new(Ended::default()), built, asked }
}

/// The callers every golden and every start is asked for, by name: anonymous,
/// each holding, nothing held, and two sessions within a ceiling.
pub fn callers() -> Vec<(&'static str, Option<AuthContext>)> {
    vec![
        ("anonymous", None),
        ("ada: editor on MENGER", Some(key(ADA, "worker-1"))),
        ("bob: editor on MENGER", Some(key(BOB, "worker-2"))),
        ("cat: editor on IDENTITY", Some(key(CAT, "worker-3"))),
        ("root: admin on *", Some(key(ROOT, "root"))),
        ("dan: holds nothing", Some(key(DAN, "dan"))),
        ("ada's session within editor@MENGER-12", Some(within(ADA, "worker-1", &["editor@MENGER-12"]))),
        ("root's session within tickets.get@*", Some(within(ROOT, "root", &["tickets.get@*"]))),
    ]
}

/// A key-proved connection (IDENTITY-40's adapter stamps `agent` and `name`).
pub fn key(p: &str, agent: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), format!("kp-{agent}"), vec![], json!({"agent": agent, "name": agent}))
}

/// A session of `p`'s within `ceiling` (IDENTITY-40: the ceiling rides in
/// the identity's metadata), as a session flow mints one.
pub fn within(p: &str, agent: &str, ceiling: &[&str]) -> AuthContext {
    AuthContext::for_principal(
        &p.parse().unwrap(),
        format!("s-{agent}"),
        vec![],
        json!({"agent": agent, "name": agent, CEILING_KEY: ceiling}),
    )
}

/// A session for `on` through `auth.login` (`auth_world` only), within
/// `ceiling` when one is given.
pub async fn session_for(w: &World, on: &AuthContext, ceiling: Option<Vec<&str>>) -> AuthContext {
    let flow = json!({"session": {"ttl_secs": 3600, "ceiling": ceiling}});
    let s = routed(w, "auth.login", json!({"flow": flow}), Some(on)).await;
    let token = s["items"][0]["content"]["token"].as_str().unwrap_or_else(|| panic!("a session: {s}")).to_string();
    let backend = w.backend.as_ref().expect("auth_world");
    backend.validate(&format!("Bearer {token}")).await.expect("the token validates")
}

// ---------------------------------------------------------------------------
// Answers, whole: every item as the wire would carry it, its clock set to 0
// ---------------------------------------------------------------------------

/// `metadata.timestamp` → 0 wherever it is: the one field that is the
/// moment of the answer, not the answer.
pub fn steady(mut v: Value) -> Value {
    if let Some(m) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        if m.contains_key("timestamp") {
            m.insert("timestamp".into(), json!(0));
        }
    }
    v
}

/// A routed call's whole answer: `{"items": [...]}`, each item serialized as
/// `PlexusStreamItem`; or `{"refused": "<the error>"}`.
pub async fn routed(w: &World, method: &str, params: Value, who: Option<&AuthContext>) -> Value {
    match w.service.route(method, params, who).await {
        Ok(s) => {
            let items: Vec<PlexusStreamItem> = s.collect().await;
            json!({"items": items.iter().map(|i| steady(serde_json::to_value(i).unwrap())).collect::<Vec<_>>()})
        }
        Err(e) => json!({"refused": e.to_string()}),
    }
}

/// The RPC module a connection with `who`'s identity is served by.
pub fn module_for(w: &World, who: Option<&AuthContext>) -> jsonrpsee::RpcModule<()> {
    let mut module = DynamicHub::arc_into_rpc_module(w.service.clone()).unwrap();
    if let Some(who) = who {
        module.extensions_mut().insert(Arc::new(who.clone()));
    }
    module
}

/// A subscription's whole answer over the module: each frame's `result`,
/// its clock set to 0, until `done` or an error.
pub async fn over_module(module: &jsonrpsee::RpcModule<()>, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let (resp, mut rx) = module.raw_json_request(&req.to_string(), 16).await.unwrap();
    let mut out = Vec::new();
    let first: Value = serde_json::from_str(resp.get()).unwrap();
    if first.get("error").is_some() {
        return json!({"error": first["error"]});
    }
    while let Ok(Some(m)) = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await {
        let v: Value = serde_json::from_str(m.get()).unwrap();
        let item = steady(v["params"]["result"].clone());
        let end = matches!(item["type"].as_str(), Some("done") | Some("error"));
        out.push(item);
        if end {
            break;
        }
    }
    json!({"frames": out})
}

/// The self-description a caller asks for, each a label and how to ask it.
pub enum Ask {
    /// A subscription on the module (`_info`, `menger.hash`, `menger.schema`).
    Module(&'static str, Value),
    /// A method through `route` (what `menger.call` dispatches).
    Routed(&'static str, Value),
    /// `menger.call` on the module.
    Call(&'static str, Value),
}

pub fn asks() -> Vec<Ask> {
    vec![
        Ask::Module("_info", json!({})),
        Ask::Module("menger.hash", json!({})),
        Ask::Module("menger.schema", json!({})),
        Ask::Module("menger.schema", json!({"method": "call"})),
        Ask::Call("tickets.schema", json!({})),
        Ask::Call("menger.hash", json!({})),
        Ask::Routed("menger.schema", json!({})),
        Ask::Routed("menger.hash", json!({})),
        Ask::Routed("menger.hashes", json!({})),
        Ask::Routed("menger.call.schema", json!({})),
        Ask::Routed("tickets.schema", json!({})),
        Ask::Routed("tickets.schema", json!({"method": "get"})),
        Ask::Routed("tickets.schema", json!({"method": "delete"})),
        Ask::Routed("tickets.set_status.schema", json!({})),
        Ask::Routed("tickets.nope.schema", json!({})),
        Ask::Routed("auth.schema", json!({})),
        Ask::Routed("auth.schema", json!({"method": "whoami"})),
        Ask::Routed("nope.schema", json!({})),
    ]
}

impl Ask {
    pub fn label(&self) -> String {
        let (how, m, p) = match self {
            Ask::Module(m, p) => ("module", m, p),
            Ask::Routed(m, p) => ("route", m, p),
            Ask::Call(m, p) => ("menger.call", m, p),
        };
        format!("{how} {m} {p}")
    }

    /// The whole answer `who` gets, on its own connection's module.
    pub async fn answer(&self, w: &World, module: &jsonrpsee::RpcModule<()>, who: Option<&AuthContext>) -> Value {
        match self {
            Ask::Module(m, p) => over_module(module, m, p.clone()).await,
            Ask::Routed(m, p) => routed(w, m, p.clone(), who).await,
            Ask::Call(m, p) => over_module(module, "menger.call", json!({"method": m, "params": p})).await,
        }
    }
}
