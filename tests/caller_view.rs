//! AUTH-4 — the caller's view, on a gated hub without the auth activation:
//! `_info`, the hub's schema and hash, and every `<ns>.schema` answered per
//! caller; an anonymous caller sees only the public methods; a hub without
//! a gate answers exactly as before.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{
    AuthContext, Gate, Membership, Memberships, PlexusStream, PlexusStreamItem, Resolve, RoleTable, ScopeRef, ViewKind,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::{json, Value};

#[derive(Clone)]
struct Tickets;

#[plexus_macros::activation(
    namespace = "tickets",
    version = "1.0.0",
    description = "AUTH-4 view fixture",
    crate_path = "plexus_core",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl Tickets {
    /// One ticket.
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// Every ticket.
    #[plexus_macros::method]
    async fn list(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "all".to_string(); }
    }

    /// Change a status.
    #[plexus_macros::method(target = "id")]
    async fn set_status(&self, id: String, status: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("{id} -> {status}"); }
    }

    /// Listed by no role.
    #[plexus_macros::method(target = "id")]
    async fn delete(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// The door.
    #[plexus_macros::method(public)]
    async fn door(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "in".to_string(); }
    }
}

/// A second activation nobody but admin holds anything of.
#[derive(Clone)]
struct Members;

#[plexus_macros::activation(namespace = "members", version = "1.0.0", description = "admin only", crate_path = "plexus_core")]
impl Members {
    /// Add a member.
    #[plexus_macros::method]
    async fn add(&self, who: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield who; }
    }
}

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CAT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ROOT: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[derive(Default)]
struct Rows(Mutex<Vec<Membership>>);
impl Rows {
    fn add(&self, who: &str, role: &str, scope: &str) {
        self.0.lock().unwrap().push(Membership {
            principal: who.parse().unwrap(),
            role: plexus_auth_core::RoleName::new(role),
            scope: ScopeRef::parse(scope),
        });
    }
}
impl Memberships for Rows {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        Some(vec![ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

fn hub() -> (Arc<DynamicHub>, Arc<Rows>) {
    let rows = Arc::new(Rows::default());
    rows.add(ADA, "editor", "MENGER");
    rows.add(BOB, "editor", "MENGER");
    rows.add(CAT, "viewer", "MENGER");
    rows.add(ROOT, "admin", "*");
    let declared = DynamicHub::new("x").register(Tickets).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let gate = Gate::new(rows.clone(), Arc::new(roles), Arc::new(Shortcodes));
    let hub = DynamicHub::new("menger")
        .register(Tickets)
        .register(Members)
        .with_gate(Arc::new(gate))
        .with_resource_metadata("http://127.0.0.1:4455/.well-known/oauth-protected-resource");
    (Arc::new(hub), rows)
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], Value::Null)
}

async fn data(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content),
                _ => None,
            }
        })
        .collect()
        .await
}

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

async fn over_module(module: &jsonrpsee::RpcModule<()>, req: Value) -> Vec<Value> {
    let (_resp, mut rx) = module.raw_json_request(&req.to_string(), 16).await.unwrap();
    let mut out = Vec::new();
    while let Ok(Some(m)) = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await {
        let v: Value = serde_json::from_str(m.get()).unwrap();
        let mut item = v["params"]["result"].clone();
        item.as_object_mut().map(|o| o.remove("metadata"));
        let done = item["type"] == "done";
        out.push(item);
        if done {
            break;
        }
    }
    out
}

#[tokio::test]
async fn anonymous_sees_the_public_methods_only() {
    let (hub, _) = hub();
    let view = hub.view(None);
    assert_eq!(view.kind, ViewKind::Anonymous);
    assert_eq!(shape(&view), BTreeMap::from([("tickets".to_string(), vec!["door".to_string()])]));
    let info = hub.info(None);
    assert_eq!(info["view"], "anonymous");
    assert_eq!(info["view_hash"], view.hash);
    assert_eq!(info["auth"], json!({"methods": ["tickets.door"],
        "resource_metadata": "http://127.0.0.1:4455/.well-known/oauth-protected-resource"}));
    // members: absent, its schema too.
    assert!(matches!(hub.route("members.schema", json!({}), None).await, Err(PlexusError::ActivationNotFound(_))));
    let root = data(hub.route("menger.schema", json!({}), None).await.unwrap()).await;
    let kids: Vec<&str> = root[0]["children"].as_array().unwrap().iter().map(|c| c["namespace"].as_str().unwrap()).collect();
    assert_eq!(kids, vec!["tickets"]);
    // The hub's own methods stay: they are how a client reaches anything.
    let names: Vec<&str> = root[0]["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"call") && names.contains(&"schema") && names.contains(&"hash"));
}

#[tokio::test]
async fn a_caller_sees_what_it_holds_with_held_on() {
    let (hub, rows) = hub();
    let ada = who(ADA);
    let view = hub.view(Some(&ada));
    assert_eq!(view.kind, ViewKind::Caller);
    assert_eq!(
        shape(&view),
        BTreeMap::from([(
            "tickets".to_string(),
            vec!["get @MENGER".to_string(), "list @MENGER".into(), "set_status @MENGER".into(), "door".into()]
        )])
    );
    let t = data(hub.route("tickets.schema", json!({}), Some(&ada)).await.unwrap()).await;
    assert_eq!(t[0]["view"], "caller");
    assert!(t[0].get("roles").is_none());
    let h = data(hub.route("menger.hashes", json!({}), Some(&ada)).await.unwrap()).await;
    assert_eq!(h[0]["hash"], view.hash);
    // Admin: everything, members too.
    let all = shape(&hub.view(Some(&who(ROOT))));
    assert_eq!(all["members"], vec!["add @*"]);
    assert!(all["tickets"].contains(&"delete @*".to_string()));
    // A membership added reaches the next view.
    let before = hub.view(Some(&who(CAT))).hash;
    rows.add(CAT, "editor", "MENGER");
    assert_ne!(hub.view(Some(&who(CAT))).hash, before);
    assert_eq!(hub.view(Some(&who(CAT))).hash, view.hash, "now holding what ADA holds, CAT sees ADA's view");
}

#[tokio::test]
async fn hashes_follow_holdings() {
    let (hub, _) = hub();
    let (a, b, c) = (hub.view(Some(&who(ADA))), hub.view(Some(&who(BOB))), hub.view(Some(&who(CAT))));
    assert_eq!(a.hash, b.hash);
    assert_ne!(a.hash, c.hash);
    assert_ne!(a.hash, hub.view(None).hash);
    assert!(hub.view(None).hash.starts_with("v-anon-"));
    assert!(a.hash.starts_with("v-") && !a.hash.starts_with("v-anon-"));
}

#[tokio::test]
async fn the_rpc_module_reads_the_connection() {
    let (hub, _) = hub();
    let mut module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    let anon = over_module(&module, json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
    assert_eq!(anon[0]["content"]["view"], "anonymous");
    module.extensions_mut().insert(Arc::new(who(ADA)));
    let info = over_module(&module, json!({"jsonrpc": "2.0", "id": 2, "method": "_info", "params": {}})).await;
    assert_eq!(info[0]["content"]["view"], "caller");
    assert_eq!(info[0]["content"]["view_hash"], hub.view(Some(&who(ADA))).hash);
    let schema = over_module(&module, json!({"jsonrpc": "2.0", "id": 3, "method": "menger.schema", "params": {}})).await;
    assert_eq!(schema[0]["content"]["hash"], info[0]["content"]["view_hash"]);
    let hash = over_module(&module, json!({"jsonrpc": "2.0", "id": 4, "method": "menger.hash", "params": {}})).await;
    assert_eq!(hash[0]["content"]["value"], info[0]["content"]["view_hash"]);
}

#[tokio::test]
async fn without_a_gate_nothing_changes() {
    let hub = Arc::new(DynamicHub::new("menger").register(Tickets).register(Members));
    // Captured from this hub shape before AUTH-4.
    let today = r#"{"auth_capabilities":{"mechanisms":[{"kind":"anonymous"}]},"backend":"menger"}"#;
    let mut module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
    assert_eq!(out[0]["content"].to_string(), today);
    module.extensions_mut().insert(Arc::new(who(ADA)));
    let out = over_module(&module, json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
    assert_eq!(out[0]["content"].to_string(), today);
    let out = over_module(&hub.as_ref().clone().into_rpc_module().unwrap(), json!({"jsonrpc": "2.0", "id": 1, "method": "_info", "params": {}})).await;
    assert_eq!(out[0]["content"].to_string(), today);
    // Every method, no view, no held_on; the hub's own hash.
    let t = data(hub.route("tickets.schema", json!({}), None).await.unwrap()).await;
    let text = t[0].to_string();
    assert!(!text.contains("\"view\"") && !text.contains("held_on"));
    assert_eq!(t[0]["methods"].as_array().unwrap().len(), 6);
    assert_eq!(hub.view(None).hash, hub.compute_hash());
    let h = data(hub.route("menger.hashes", json!({}), None).await.unwrap()).await;
    assert_eq!(h[0]["hash"], hub.compute_hash());
}
