//! AUTH-4 + AUTH-5, end to end: a gated hub with the `auth` activation and
//! the reference in-memory backend and stores. What each caller can
//! discover (`_info`, every schema, the hub's hash) is exactly what it can
//! use; the auth activation signs people and agents in, says who they are
//! and what a method needs, and lets an admin shape roles and memberships.
//!
//! Run with `--nocapture` to see the wire samples each test prints.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{
    error_item, AuthBackend, AuthContext, AuthSetup, MemoryAuthBackend, MemoryMemberships, MemoryRoles, PlexusStream,
    PlexusStreamItem, Reach, Resolve, ScopeRef, SessionValidator, ViewKind,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// The service: a tickets activation, shortcode scopes
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Tickets;

#[plexus_macros::activation(
    namespace = "tickets",
    version = "0.5.0",
    description = "Plans as data",
    crate_path = "plexus_core",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl Tickets {
    /// One ticket by id.
    #[plexus_macros::method(target = "id", description = "One ticket by id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// Tickets, from where the caller holds them.
    #[plexus_macros::method(description = "Tickets, filtered and paged")]
    async fn list(&self, reach: Reach) -> impl Stream<Item = String> + Send + 'static {
        let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        stream! { yield held.join(","); }
    }

    /// Change a ticket's status.
    #[plexus_macros::method(target = "id", description = "Change a ticket's status")]
    async fn set_status(&self, auth: &AuthContext, id: String, status: String) -> impl Stream<Item = String> + Send + 'static {
        let _ = auth;
        stream! { yield format!("{id} -> {status}"); }
    }

    /// Listed by no role: admin only.
    #[plexus_macros::method(target = "id", description = "Delete a ticket")]
    async fn delete(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }
}

/// `CODE-n` → `[CODE-n, CODE, *]`; `CODE` → `[CODE, *]`.
struct Shortcodes;
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

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CAT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ROOT: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const NEW: &str = "key:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const MENGER_ADMIN: &str = "key:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const ROOT_ID: &str = "11111111-2222-4333-8444-555555555555";

struct World {
    hub: Arc<DynamicHub>,
    backend: Arc<MemoryAuthBackend>,
}

fn world() -> World {
    let backend = Arc::new(
        MemoryAuthBackend::new("http://127.0.0.1:4456/login").with_user("root", "hunter2", &format!("idp:{ROOT_ID}"), Some("Root")),
    );
    let roles = Arc::new(MemoryRoles::default());
    let memberships = Arc::new(
        MemoryMemberships::new()
            .with(ADA, "editor", "MENGER")
            .with(BOB, "editor", "MENGER")
            .with(CAT, "editor", "IDENTITY")
            .with(ROOT, "admin", "*")
            .with(&format!("idp:{ROOT_ID}"), "admin", "*")
            .with(MENGER_ADMIN, "admin", "MENGER"),
    );
    let hub = DynamicHub::new("menger")
        .register(Tickets)
        .with_auth(AuthSetup::new(backend.clone(), roles.clone(), memberships, Arc::new(Shortcodes)))
        .with_resource_metadata("http://127.0.0.1:4456/.well-known/oauth-protected-resource");
    roles.seed(&hub.declared_roles());
    World { hub: Arc::new(hub), backend }
}

/// A key-proved connection (IDENTITY-40's adapter stamps `agent` and `name`).
fn key(p: &str, agent: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "kp-1", vec![], json!({"agent": agent, "name": agent}))
}

/// Items of a stream: data contents and error items, as the wire sends them.
async fn items(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content),
                PlexusStreamItem::Error { message, .. } => Some(json!({"error": message})),
                _ => None,
            }
        })
        .collect()
        .await
}

async fn call(w: &World, method: &str, params: Value, who: Option<&AuthContext>) -> Result<Vec<Value>, PlexusError> {
    match w.hub.route(method, params, who).await {
        Ok(s) => Ok(items(s).await),
        Err(e) => Err(e),
    }
}

async fn one(w: &World, method: &str, params: Value, who: Option<&AuthContext>) -> Value {
    let out = call(w, method, params, who).await.unwrap_or_else(|e| panic!("{method}: {e}"));
    assert_eq!(out.len(), 1, "{method}: {out:?}");
    out.into_iter().next().unwrap()
}

/// Sign in with a session: password for a person, the session flow on a
/// key-proved connection for an agent. Answers the session's identity.
async fn session_for(w: &World, on: &AuthContext, ceiling: Option<Vec<&str>>) -> (Value, AuthContext) {
    let flow = json!({"session": {"ttl_secs": 3600, "ceiling": ceiling}});
    let s = one(w, "auth.login", json!({"flow": flow}), Some(on)).await;
    assert_eq!(s["type"], "session", "{s}");
    let ctx = w.backend.validate(&format!("Bearer {}", s["token"].as_str().unwrap())).await.expect("the token validates");
    (s, ctx)
}

/// `{ns: [method (held_on…)]}` of a view, `schema` left out.
fn shape(view: &plexus_core::plexus::View) -> BTreeMap<String, Vec<String>> {
    view.activations
        .iter()
        .map(|(ns, s)| {
            let ms = s
                .methods
                .iter()
                .filter(|m| m.name != "schema")
                .map(|m| match &m.held_on {
                    Some(h) => format!("{} @{}", m.name, h.join(",")),
                    None => m.name.clone(),
                })
                .collect();
            (ns.clone(), ms)
        })
        .collect()
}

fn module_items(raw: &str) -> Value {
    let v: Value = serde_json::from_str(raw).unwrap();
    let mut r = v["params"]["result"].clone();
    if let Some(o) = r.as_object_mut() {
        o.remove("metadata");
    }
    r
}

async fn over_module(module: &jsonrpsee::RpcModule<()>, req: Value) -> Vec<Value> {
    let (_resp, mut rx) = module.raw_json_request(&req.to_string(), 16).await.unwrap();
    let mut out = Vec::new();
    while let Ok(Some(m)) = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await {
        let item = module_items(m.get());
        let done = item["type"] == "done";
        out.push(item);
        if done {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// AUTH-4: the anonymous view
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anonymous_sees_only_the_door() {
    let w = world();
    let info = w.hub.info(None);
    println!("ANON _info: {info}");
    assert_eq!(info["backend"], "menger");
    assert_eq!(info["view"], "anonymous");
    assert!(info["view_hash"].as_str().unwrap().starts_with("v-anon-"));
    assert_eq!(info["auth"]["methods"], json!(["auth.providers", "auth.login", "auth.signup"]));
    assert_eq!(info["auth"]["resource_metadata"], "http://127.0.0.1:4456/.well-known/oauth-protected-resource");
    // Older clients keep reading what they read.
    assert_eq!(info["auth_capabilities"], json!({"mechanisms": [{"kind": "anonymous"}]}));

    let view = w.hub.view(None);
    assert_eq!(view.kind, ViewKind::Anonymous);
    assert_eq!(
        shape(&view),
        BTreeMap::from([("auth".to_string(), vec!["providers".to_string(), "login".into(), "signup".into()])])
    );

    // menger.schema: the hub's own methods and one child, auth.
    let root = one(&w, "menger.schema", json!({}), None).await;
    println!("ANON menger.schema: {}", json!({"namespace": root["namespace"], "hash": root["hash"], "view": root["view"], "children": root["children"]}));
    assert_eq!(root["view"], "anonymous");
    assert_eq!(root["hash"], info["view_hash"]);
    let kids: Vec<&str> = root["children"].as_array().unwrap().iter().map(|c| c["namespace"].as_str().unwrap()).collect();
    assert_eq!(kids, vec!["auth"]);
    let auth = one(&w, "auth.schema", json!({}), None).await;
    let names: Vec<&str> = auth["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["providers", "login", "signup", "schema"]);
    assert!(auth["methods"].as_array().unwrap()[..3].iter().all(|m| m["public"] == true));
    // tickets is not there at all — not even its schema.
    assert!(matches!(call(&w, "tickets.schema", json!({}), None).await, Err(PlexusError::ActivationNotFound(_))));
    assert!(matches!(
        call(&w, "auth.schema", json!({"method": "whoami"}), None).await,
        Err(PlexusError::MethodNotFound { .. })
    ));
    assert!(matches!(call(&w, "auth.whoami.schema", json!({}), None).await, Err(PlexusError::MethodNotFound { .. })));
    // The hash the hub answers is the view's.
    let h = one(&w, "menger.hash", json!({}), None).await;
    assert_eq!(h["value"], info["view_hash"]);
    // The door works; nothing else does.
    let providers = call(&w, "auth.providers", json!({}), None).await.unwrap();
    println!("ANON auth.providers: {}", json!(providers));
    assert!(providers.iter().any(|p| p["kind"] == "browser"));
    assert!(matches!(call(&w, "auth.whoami", json!({}), None).await, Err(PlexusError::Unauthenticated(_))));
}

#[tokio::test]
async fn the_rpc_module_answers_info_and_schema_per_connection() {
    let w = world();
    // No identity on the connection: the anonymous view.
    let module = DynamicHub::arc_into_rpc_module(w.hub.clone()).unwrap();
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
    println!("WIRE anonymous _info: {}", out[0]);
    assert_eq!(out[0]["content"], w.hub.info(None));
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 2, "method": "menger.call",
        "params": {"method": "menger.schema", "params": {}}})).await;
    assert_eq!(out[0]["content"]["view"], "anonymous");

    // A signed-in connection: the transport puts its identity in the
    // connection's extensions (here, the module's).
    let (_, ada) = session_for(&w, &key(ADA, "worker-1"), None).await;
    let mut module = DynamicHub::arc_into_rpc_module(w.hub.clone()).unwrap();
    module.extensions_mut().insert(Arc::new(ada.clone()));
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 3, "method": "_info", "params": {}})).await;
    println!("WIRE caller _info: {}", out[0]);
    assert_eq!(out[0]["content"]["view"], "caller");
    assert!(out[0]["content"].get("auth").is_none());
    assert_eq!(out[0]["content"]["view_hash"], w.hub.view(Some(&ada)).hash);
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 4, "method": "menger.schema", "params": {}})).await;
    assert_eq!(out[0]["content"]["hash"], w.hub.view(Some(&ada)).hash);
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 5, "method": "menger.hash", "params": {}})).await;
    assert_eq!(out[0]["content"]["value"], w.hub.view(Some(&ada)).hash);
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 6, "method": "menger.call",
        "params": {"method": "tickets.schema", "params": {}}})).await;
    let t = &out[0]["content"];
    println!(
        "WIRE caller tickets.schema: {}",
        json!({"namespace": t["namespace"], "hash": t["hash"], "view": t["view"],
               "methods": t["methods"].as_array().unwrap().iter().map(|m| json!({"name": m["name"], "grant": m["grant"], "target": m["target"], "held_on": m["held_on"]})).collect::<Vec<_>>()})
    );
    assert_eq!(t["view"], "caller");
    // A call on that connection carries its identity through `<ns>.call`.
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 7, "method": "menger.call",
        "params": {"method": "tickets.set_status", "params": {"id": "IDENTITY-1", "status": "Ready"}}})).await;
    println!("WIRE refusal: {}", out[0]);
    assert_eq!(out[0]["error_kind"], "forbidden");
    assert_eq!(out[0]["grant"], "tickets.set_status");
    assert_eq!(out[0]["held_on"], json!(["MENGER"]));

    // into_rpc_module reads the connection's identity too, under a gate.
    let mut module = w.hub.as_ref().clone().into_rpc_module().unwrap();
    module.extensions_mut().insert(Arc::new(ada.clone()));
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 8, "method": "_info", "params": {}})).await;
    assert_eq!(out[0]["content"]["view"], "caller");
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 9, "method": "menger.call",
        "params": {"method": "tickets.get", "params": {"id": "MENGER-1"}}})).await;
    assert_eq!(out[0]["content"], "MENGER-1");
}

// ---------------------------------------------------------------------------
// AUTH-4: the caller's view
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_signed_in_view_lists_exactly_the_held_methods() {
    let w = world();
    let (session, ada) = session_for(&w, &key(ADA, "worker-1"), None).await;
    println!("WIRE auth.login session (agent): {session}");
    let view = w.hub.view(Some(&ada));
    assert_eq!(view.kind, ViewKind::Caller);
    assert!(view.hash.starts_with("v-") && !view.hash.starts_with("v-anon-"));
    assert_eq!(
        shape(&view),
        BTreeMap::from([
            (
                "auth".to_string(),
                vec!["providers".to_string(), "login".into(), "signup".into(), "whoami".into(), "logout".into(), "requires".into()]
            ),
            ("tickets".to_string(), vec!["get @MENGER".to_string(), "list @MENGER".into(), "set_status @MENGER".into()]),
        ])
    );
    // Absent, not marked: delete, and the admin's auth methods.
    let tickets = &view.activations["tickets"];
    assert!(tickets.methods.iter().all(|m| m.name != "delete"));
    assert!(tickets.roles.is_empty(), "declared roles name methods the caller may not see");
    let set_status = tickets.methods.iter().find(|m| m.name == "set_status").unwrap();
    assert_eq!(set_status.grant.as_deref(), Some("tickets.set_status"));
    assert_eq!(set_status.target.as_deref(), Some("id"));
    // Each schema answers from the view.
    let t = one(&w, "tickets.schema", json!({}), Some(&ada)).await;
    assert_eq!(t["hash"], tickets.hash);
    assert!(matches!(
        call(&w, "tickets.schema", json!({"method": "delete"}), Some(&ada)).await,
        Err(PlexusError::MethodNotFound { .. })
    ));
    let m = one(&w, "tickets.set_status.schema", json!({}), Some(&ada)).await;
    assert_eq!(m["held_on"], json!(["MENGER"]));

    // Admin: every method, held everywhere.
    let root = key(ROOT, "root");
    let all = shape(&w.hub.view(Some(&root)));
    assert_eq!(all["tickets"], vec!["get @*", "list @*", "set_status @*", "delete @*"]);
    assert!(all["auth"].contains(&"role_set @*".to_string()) && all["auth"].contains(&"waiting @*".to_string()));

    // A ceiling narrows the view: an agent's session within MENGER-12.
    let (narrow_session, narrow) = session_for(&w, &key(ADA, "worker-1"), Some(vec!["editor@MENGER-12"])).await;
    assert_eq!(narrow_session["ceiling"], json!(["editor@MENGER-12"]));
    let v = w.hub.view(Some(&narrow));
    assert_eq!(shape(&v)["tickets"], vec!["get @MENGER-12", "list @MENGER-12", "set_status @MENGER-12"]);
    // …and whoami / logout still answer under any ceiling.
    let me = one(&w, "auth.whoami", json!({}), Some(&narrow)).await;
    assert_eq!(me["ceiling"], json!(["editor@MENGER-12"]));
}

#[tokio::test]
async fn the_same_holdings_share_a_view_hash() {
    let w = world();
    let ada = key(ADA, "a");
    let bob = key(BOB, "b");
    let cat = key(CAT, "c");
    let root = key(ROOT, "r");
    let (a, b, c, r) = (w.hub.view(Some(&ada)), w.hub.view(Some(&bob)), w.hub.view(Some(&cat)), w.hub.view(Some(&root)));
    println!("HASHES editor@MENGER {} {} · editor@IDENTITY {} · admin@* {} · anonymous {}", a.hash, b.hash, c.hash, r.hash, w.hub.view(None).hash);
    assert_eq!(a.hash, b.hash, "two editors on MENGER see one view");
    assert_eq!(a.activations["tickets"].hash, b.activations["tickets"].hash);
    assert_ne!(a.hash, c.hash, "editor on IDENTITY holds it elsewhere: held_on differs");
    assert_ne!(a.hash, r.hash);
    assert_ne!(a.hash, w.hub.view(None).hash);
    // Deterministic: asked again, the same.
    assert_eq!(w.hub.view(Some(&ada)).hash, a.hash);
    assert_eq!(w.hub.view(None).hash, w.hub.view(None).hash);
}

// ---------------------------------------------------------------------------
// AUTH-5: whoami, requires, roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whoami_requires_and_roles() {
    let w = world();
    let (_, ada) = session_for(&w, &key(ADA, "worker-1"), Some(vec!["editor@MENGER-12"])).await;
    let me = one(&w, "auth.whoami", json!({}), Some(&ada)).await;
    println!("WIRE auth.whoami: {me}");
    assert_eq!(
        me,
        json!({"type": "whoami", "principal": ADA, "name": "worker-1", "agent": "worker-1",
               "memberships": [{"role": "editor", "scope": "MENGER"}], "ceiling": ["editor@MENGER-12"]})
    );

    let req = one(&w, "auth.requires", json!({"method": "tickets.set_status"}), Some(&ada)).await;
    println!("WIRE auth.requires: {req}");
    assert_eq!(
        req,
        json!({"type": "requires", "method": "tickets.set_status", "grant": "tickets.set_status",
               "target": "id", "roles": ["editor", "admin"]})
    );
    let req = one(&w, "auth.requires", json!({"method": "auth.login"}), Some(&ada)).await;
    assert_eq!(req["public"], true);
    let req = one(&w, "auth.requires", json!({"method": "tickets.nope"}), Some(&ada)).await;
    assert_eq!(req["type"], "error");
    // requires is not public.
    assert!(matches!(
        call(&w, "auth.requires", json!({"method": "tickets.get"}), None).await,
        Err(PlexusError::Unauthenticated(_))
    ));

    // roles: admin's (auth.roles is listed by no role but admin).
    let roles = call(&w, "auth.roles", json!({}), Some(&key(ROOT, "r"))).await.unwrap();
    println!("WIRE auth.roles: {}", json!(roles));
    assert_eq!(roles[0], json!({"type": "role", "role": "admin", "grants": [], "all": true}));
    let editor = roles.iter().find(|r| r["role"] == "editor").unwrap();
    assert_eq!(editor["grants"], json!(["tickets.get", "tickets.list", "tickets.set_status"]));
    let member = roles.iter().find(|r| r["role"] == "member").unwrap();
    assert_eq!(member["grants"], json!(["auth.logout", "auth.requires", "auth.whoami"]));
    let err = call(&w, "auth.roles", json!({}), Some(&ada)).await.err().unwrap();
    assert!(matches!(err, PlexusError::Forbidden { .. }), "{err}");
}

// ---------------------------------------------------------------------------
// AUTH-5: an admin shapes roles and memberships
// ---------------------------------------------------------------------------

#[tokio::test]
async fn role_set_changes_the_next_view() {
    let w = world();
    let ada = key(ADA, "a");
    let before = w.hub.view(Some(&ada));
    let root = key(ROOT, "r");
    let out = one(&w, "auth.role_set", json!({"role": "editor", "grants": ["tickets.get"]}), Some(&root)).await;
    println!("WIRE auth.role_set: {out}");
    assert_eq!(out, json!({"type": "role", "role": "editor", "grants": ["tickets.get"]}));
    let after = w.hub.view(Some(&ada));
    assert_eq!(shape(&after)["tickets"], vec!["get @MENGER"]);
    assert_ne!(before.hash, after.hash);
    // …and the next call: set_status is refused now.
    let err = call(&w, "tickets.set_status", json!({"id": "MENGER-1", "status": "Ready"}), Some(&ada)).await.err().unwrap();
    assert!(matches!(err, PlexusError::Forbidden { .. }));
    // A role may include another; unknown grants and admin are refused.
    let out = one(&w, "auth.role_set", json!({"role": "triager", "grants": ["viewer", "tickets.set_status"]}), Some(&root)).await;
    assert_eq!(out["grants"], json!(["tickets.get", "tickets.list", "tickets.set_status"]));
    let out = one(&w, "auth.role_set", json!({"role": "x", "grants": ["tickets.nope"]}), Some(&root)).await;
    assert_eq!(out["type"], "error");
    let out = one(&w, "auth.role_set", json!({"role": "admin", "grants": []}), Some(&root)).await;
    assert_eq!(out["type"], "error");
    // Admin on MENGER only is not admin on *: refused in band, typed.
    let out = one(&w, "auth.role_set", json!({"role": "editor", "grants": []}), Some(&key(MENGER_ADMIN, "m"))).await;
    println!("WIRE auth.role_set refused in band: {out}");
    assert_eq!(out["error_kind"], "forbidden");
    assert_eq!(out["grant"], "auth.role_set");
    assert_eq!(out["scope"], "*");
    assert_eq!(out["held_on"], json!(["MENGER"]));
}

#[tokio::test]
async fn grant_and_revoke_by_admin_refused_otherwise() {
    let w = world();
    let root = key(ROOT, "r");
    let ada = key(ADA, "a");
    assert!(shape(&w.hub.view(Some(&ada)))["tickets"].iter().all(|m| !m.contains("IDENTITY")));
    let out = one(&w, "auth.grant", json!({"principal": ADA, "role": "viewer", "scope": "IDENTITY"}), Some(&root)).await;
    println!("WIRE auth.grant: {out}");
    assert_eq!(out, json!({"type": "granted", "principal": ADA, "role": "viewer", "scope": "IDENTITY"}));
    assert_eq!(shape(&w.hub.view(Some(&ada)))["tickets"], vec!["get @IDENTITY,MENGER", "list @IDENTITY,MENGER", "set_status @MENGER"]);

    // An admin on MENGER grants on MENGER, not on IDENTITY.
    let madmin = key(MENGER_ADMIN, "m");
    let out = one(&w, "auth.grant", json!({"principal": CAT, "role": "viewer", "scope": "MENGER"}), Some(&madmin)).await;
    assert_eq!(out["type"], "granted");
    let err = call(&w, "auth.grant", json!({"principal": CAT, "role": "viewer", "scope": "IDENTITY"}), Some(&madmin)).await.err().unwrap();
    // A non-admin: the gate's typed refusal.
    let err2 = call(&w, "auth.grant", json!({"principal": BOB, "role": "admin", "scope": "MENGER"}), Some(&ada)).await.err().unwrap();
    let mut wire = error_item("menger", &err2);
    wire.as_object_mut().unwrap().remove("metadata");
    println!("WIRE auth.grant refused: {wire}");
    assert_eq!(
        wire,
        json!({"type": "error", "error_kind": "forbidden", "grant": "auth.grant", "scope": "MENGER",
               "roles": ["admin"], "held_on": [], "message": "needs auth.grant on MENGER",
               "code": "-32003", "recoverable": false})
    );
    assert!(matches!(err, PlexusError::Forbidden { .. }));
    // Granting on * needs admin on *.
    let err = call(&w, "auth.grant", json!({"principal": CAT, "role": "viewer", "scope": "*"}), Some(&madmin)).await.err().unwrap();
    assert_eq!(err.to_string(), "needs auth.grant");
    // An unknown role, a bad principal.
    let out = one(&w, "auth.grant", json!({"principal": CAT, "role": "nope", "scope": "MENGER"}), Some(&root)).await;
    assert_eq!(out["type"], "error");
    let out = one(&w, "auth.grant", json!({"principal": "nobody", "role": "viewer", "scope": "MENGER"}), Some(&root)).await;
    assert_eq!(out["type"], "error");

    // Revoke: one role, then every role on a scope.
    let out = one(&w, "auth.revoke", json!({"principal": ADA, "role": "viewer", "scope": "IDENTITY"}), Some(&root)).await;
    println!("WIRE auth.revoke: {out}");
    assert_eq!(out, json!({"type": "revoked", "principal": ADA, "scope": "IDENTITY", "roles": ["viewer"]}));
    let out = one(&w, "auth.revoke", json!({"principal": ADA, "scope": "MENGER"}), Some(&root)).await;
    assert_eq!(out["roles"], json!(["editor"]));
    // ADA now holds nothing: the auth basics and the door only.
    let v = w.hub.view(Some(&ada));
    assert_eq!(shape(&v).keys().collect::<Vec<_>>(), vec!["auth"]);
    assert!(matches!(call(&w, "auth.revoke", json!({"principal": BOB, "scope": "MENGER"}), Some(&ada)).await, Err(PlexusError::Forbidden { .. })));
}

#[tokio::test]
async fn signup_waits_and_an_admin_sees_it() {
    let w = world();
    // Anonymous: the reference backend says to sign in first.
    let out = one(&w, "auth.signup", json!({}), None).await;
    assert_eq!(out["type"], "error");
    // A key-proved agent holding nothing asks for access.
    let newbie = key(NEW, "worker-9");
    let out = one(&w, "auth.signup", json!({}), Some(&newbie)).await;
    println!("WIRE auth.signup: {out}");
    assert_eq!(out["type"], "waiting");
    assert_eq!(out["principal"], NEW);
    let since = out["since"].clone();
    // Asking again keeps its place.
    assert_eq!(one(&w, "auth.signup", json!({}), Some(&newbie)).await["since"], since);
    // Its view: who am I, and the door — nothing else.
    assert_eq!(shape(&w.hub.view(Some(&newbie))).keys().collect::<Vec<_>>(), vec!["auth"]);

    let root = key(ROOT, "r");
    let list = call(&w, "auth.waiting", json!({}), Some(&root)).await.unwrap();
    println!("WIRE auth.waiting: {}", json!(list));
    assert_eq!(list, vec![json!({"type": "waiting", "principal": NEW, "name": "worker-9", "provider": "key", "since": since})]);
    // Not for a non-admin; admin on MENGER only is refused in band.
    assert!(matches!(call(&w, "auth.waiting", json!({}), Some(&key(ADA, "a"))).await, Err(PlexusError::Forbidden { .. })));
    assert_eq!(one(&w, "auth.waiting", json!({}), Some(&key(MENGER_ADMIN, "m"))).await["error_kind"], "forbidden");
    // Granted, it leaves the list.
    one(&w, "auth.grant", json!({"principal": NEW, "role": "viewer", "scope": "MENGER"}), Some(&root)).await;
    assert!(call(&w, "auth.waiting", json!({}), Some(&root)).await.unwrap().is_empty());
    // A member signing up is the backend's to answer.
    assert_eq!(one(&w, "auth.signup", json!({}), Some(&newbie)).await["type"], "error");
}

// ---------------------------------------------------------------------------
// AUTH-5: the login flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_person_signs_in_through_the_browser() {
    let w = world();
    let url = one(&w, "auth.login", json!({"flow": {"browser": {"redirect": "http://127.0.0.1:53817/cb"}}}), None).await;
    println!("WIRE auth.login browser: {url}");
    assert_eq!(url["type"], "login_url");
    let state = url["state"].as_str().unwrap().to_string();
    assert!(url["url"].as_str().unwrap().starts_with("http://127.0.0.1:4456/login?cli=1&state=s_"));
    // The service's web sign-in finishes, and sends the browser back.
    let (back, code) = w.backend.complete_browser(&state, &format!("idp:{ROOT_ID}"), Some("Ada Lovelace")).unwrap();
    assert_eq!(back, format!("http://127.0.0.1:53817/cb?code={code}&state={state}"));
    // A code for another state is refused, and spends the code.
    let s = one(&w, "auth.login", json!({"flow": {"code": {"code": code, "state": state}}}), None).await;
    println!("WIRE auth.login code: {s}");
    assert_eq!(s["type"], "session");
    assert_eq!(s["name"], "Ada Lovelace");
    assert_eq!(s["principal"], format!("idp:{ROOT_ID}"));
    let again = one(&w, "auth.login", json!({"flow": {"code": {"code": code, "state": state}}}), None).await;
    assert_eq!(again["type"], "error", "single use");
    let ctx = w.backend.validate(&format!("access_token={}; other=1", s["token"].as_str().unwrap())).await.unwrap();
    assert_eq!(w.hub.view(Some(&ctx)).activations["tickets"].methods.iter().filter(|m| m.name != "schema").count(), 4);
    // Logout ends it.
    assert_eq!(one(&w, "auth.logout", json!({}), Some(&ctx)).await["type"], "logged_out");
    assert!(w.backend.validate(s["token"].as_str().unwrap()).await.is_none());
    // A non-loopback redirect is refused.
    let bad = one(&w, "auth.login", json!({"flow": {"browser": {"redirect": "https://evil.example/cb"}}}), None).await;
    assert_eq!(bad["type"], "error");
}

#[tokio::test]
async fn password_and_session_flows() {
    let w = world();
    let s = one(&w, "auth.login", json!({"flow": {"password": {"username": "root", "password": "hunter2"}}}), None).await;
    assert_eq!(s["type"], "session");
    let bad = one(&w, "auth.login", json!({"flow": {"password": {"username": "root", "password": "x"}}}), None).await;
    assert_eq!(bad["type"], "error");
    // The session flow needs a connection that is someone.
    let anon = one(&w, "auth.login", json!({"flow": {"session": {}}}), None).await;
    assert_eq!(anon["type"], "error");
    // A malformed ceiling is refused before the backend.
    let bad = one(&w, "auth.login", json!({"flow": {"session": {"ceiling": ["editor"]}}}), Some(&key(ADA, "a"))).await;
    assert_eq!(bad["type"], "error");
    // A session minted on a session layers its ceiling: never wider.
    let (_, first) = session_for(&w, &key(ADA, "worker-1"), Some(vec!["editor@MENGER-12"])).await;
    let (second, ctx) = session_for(&w, &first, Some(vec!["editor@MENGER"])).await;
    assert_eq!(second["ceiling"], json!(["editor@MENGER"]));
    assert_eq!(shape(&w.hub.view(Some(&ctx)))["tickets"], vec!["get @MENGER-12", "list @MENGER-12", "set_status @MENGER-12"]);
}

/// AUTH-11 (AUTH-10 finding #1): a session that signed out holds nothing on
/// the socket that carried it — not `auth.grant`, not `auth.role_set`, not
/// `auth.waiting`, not a service method — and sees the anonymous view. The
/// review's attack: an admin's session logs out, then the same connection
/// grants a fresh key admin on `*`.
#[tokio::test]
async fn a_session_that_signed_out_cannot_grant() {
    let w = world();
    let (_, admin) = session_for(&w, &key(ROOT, "boss"), None).await;
    assert_eq!(one(&w, "auth.whoami", json!({}), Some(&admin)).await["principal"], ROOT);
    assert_eq!(one(&w, "auth.logout", json!({}), Some(&admin)).await["type"], "logged_out");

    let err = call(&w, "auth.grant", json!({"principal": NEW, "role": "admin", "scope": "*"}), Some(&admin)).await.err().unwrap();
    let mut wire = error_item("menger", &err);
    wire.as_object_mut().unwrap().remove("metadata");
    println!("WIRE auth.grant after logout: {wire}");
    assert_eq!(wire["error_kind"], "unauthenticated");
    assert_eq!(wire["message"], "Authentication required: you have signed out: sign in again");
    for (method, params) in [
        ("auth.role_set", json!({"role": "viewer", "grants": ["tickets.get"]})),
        ("auth.revoke", json!({"principal": ADA, "scope": "MENGER"})),
        ("auth.waiting", json!({})),
        ("auth.whoami", json!({})),
        ("tickets.set_status", json!({"id": "MENGER-1", "status": "Done"})),
        ("tickets.list", json!({})),
    ] {
        let err = call(&w, method, params, Some(&admin)).await.err().unwrap_or_else(|| panic!("{method} answered after logout"));
        assert!(matches!(err, PlexusError::Unauthenticated(_)), "{method}: {err:?}");
    }
    // NEW holds nothing; the memberships are as they were.
    assert_eq!(shape(&w.hub.view(Some(&key(NEW, "n")))).keys().collect::<Vec<_>>(), vec!["auth"]);
    assert_eq!(w.hub.view(Some(&admin)).kind, ViewKind::Anonymous);
    // The door stays open: it may sign in again.
    assert!(!call(&w, "auth.providers", json!({}), Some(&admin)).await.expect("the door is public").is_empty());
}

/// AUTH-13 (AUTH-10 finding #3): `get(id)` and `delete(id)` take one param,
/// their target. A bare value names no target — before, the gate decided it
/// as "held anywhere" and the method took the value as `id`: an editor of
/// MENGER read IDENTITY-1, an admin of MENGER deleted it. Now any call whose
/// params are not an object is refused, typed, and so is a target the gate
/// cannot read.
#[tokio::test]
async fn a_bare_value_reaches_no_target() {
    let w = world();
    let ada = key(ADA, "a");
    let madmin = key(MENGER_ADMIN, "m");
    // The shape that works, refused where it should be.
    assert!(matches!(call(&w, "tickets.get", json!({"id": "IDENTITY-1"}), Some(&ada)).await, Err(PlexusError::Forbidden { .. })));
    assert!(matches!(call(&w, "tickets.delete", json!({"id": "IDENTITY-1"}), Some(&madmin)).await, Err(PlexusError::Forbidden { .. })));

    for (who, method, params) in [
        (&ada, "tickets.get", json!("IDENTITY-1")),
        (&madmin, "tickets.delete", json!("IDENTITY-1")),
        (&ada, "tickets.get", json!(["IDENTITY-1"])),
        (&ada, "tickets.get", json!(7)),
        (&ada, "tickets.set_status", json!(["IDENTITY-1", "Done"])),
        (&ada, "tickets.get", json!({"id": {"id": "IDENTITY-1"}})),
        (&ada, "tickets.get", json!({"id": [{"id": "IDENTITY-1"}]})),
        (&ada, "tickets.list", json!("IDENTITY")),
    ] {
        let err = call(&w, method, params.clone(), Some(who)).await.err().unwrap_or_else(|| panic!("{method} {params} answered"));
        let wire = error_item("menger", &err);
        assert_eq!(wire["error_kind"], "invalid_params", "{method} {params}: {wire}");
    }
    let err = call(&w, "tickets.get", json!("IDENTITY-1"), Some(&ada)).await.err().unwrap();
    let mut wire = error_item("menger", &err);
    wire.as_object_mut().unwrap().remove("metadata");
    println!("WIRE tickets.get \"IDENTITY-1\": {wire}");
    // Absent params are still no params.
    assert!(call(&w, "tickets.list", Value::Null, Some(&ada)).await.is_ok());
    // Anonymous: the shape is refused before anything is decided.
    assert!(matches!(call(&w, "tickets.get", json!("MENGER-1"), None).await, Err(PlexusError::InvalidParams(_))));

    // The macro refuses it too, with no gate in front: a method with a
    // target never takes its target as a bare value.
    let bare = Arc::new(DynamicHub::new("menger").register(Tickets));
    assert!(matches!(bare.route("tickets.get", json!("MENGER-1"), None).await, Err(PlexusError::InvalidParams(_))));
    assert!(bare.route("tickets.get", json!({"id": "MENGER-1"}), None).await.is_ok());
}

// ---------------------------------------------------------------------------
// Without a gate: nothing changes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_gateless_hub_answers_info_byte_for_byte() {
    let hub = Arc::new(DynamicHub::new("menger").register(Tickets));
    // Today's payload, captured before AUTH-4 from this same hub shape.
    let today = r#"{"auth_capabilities":{"mechanisms":[{"kind":"anonymous"}]},"backend":"menger"}"#;
    for module in [DynamicHub::arc_into_rpc_module(hub.clone()).unwrap(), hub.as_ref().clone().into_rpc_module().unwrap()] {
        let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
        assert_eq!(out[0]["content"].to_string(), today);
    }
    // …whoever asks: an identity on the connection changes nothing.
    let mut module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    module.extensions_mut().insert(Arc::new(key(ADA, "a")));
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
    assert_eq!(out[0]["content"].to_string(), today);
    assert_eq!(hub.info(Some(&key(ADA, "a"))).to_string(), today);
    // Schemas carry no view, no held_on; the hash is the hub's own.
    let s = one(&World { hub: hub.clone(), backend: Arc::new(MemoryAuthBackend::new("x")) }, "tickets.schema", json!({}), None).await;
    let text = s.to_string();
    assert!(!text.contains("\"view\"") && !text.contains("held_on"), "{text}");
    assert!(text.contains("\"roles\""), "declared roles stay on a gate-less schema");
    let v = hub.view(None);
    assert_eq!(v.hash, hub.compute_hash());
    assert_eq!(v.activations.len(), 1);
    let h = over_module(&module, json!({"jsonrpc": "2.0", "id": 2, "method": "menger.hash", "params": {}})).await;
    assert_eq!(h[0]["content"]["value"], hub.compute_hash());
    let _: &dyn AuthBackend = &MemoryAuthBackend::new("x");
}
