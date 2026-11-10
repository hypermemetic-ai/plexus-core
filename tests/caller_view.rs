//! AUTH-4 — the caller's view, on a gated hub without the auth activation:
//! `_info`, the hub's schema and hash, and every `<ns>.schema` answered per
//! caller; an anonymous caller sees only the public methods; a hub without
//! a gate answers exactly as before.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{AuthContext, PlexusStream, PlexusStreamItem, ViewKind};
use plexus_core::{DynamicHub, PlexusError};
use plexus_testkit::parts::{who, Members, Shortcodes};
use plexus_testkit::World;
use serde_json::{json, Value};

#[derive(Clone)]
struct TicketsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "AUTH-4 view fixture",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl TicketsActivation {
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
struct MembersActivation;

#[plexus_macros::activation(version = "1.0.0", description = "admin only")]
impl MembersActivation {
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

/// The gated service and its memberships: ADA and BOB edit MENGER, CAT
/// views it, ROOT is admin; a ticket lives in its shortcode.
async fn served() -> (Arc<DynamicHub>, Arc<Members>) {
    let host = World::new()
        .host()
        .named("menger")
        .with(TicketsActivation)
        .with(MembersActivation)
        .configure(|s| s.with_resource_metadata("http://127.0.0.1:4455/.well-known/oauth-protected-resource"))
        .resolving(Shortcodes)
        .without_named_callers()
        .member_at(ADA, "editor", "MENGER")
        .member_at(BOB, "editor", "MENGER")
        .member_at(CAT, "viewer", "MENGER")
        .member(ROOT, "admin")
        .await;
    (host.service().clone(), host.members().clone())
}

async fn data(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
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
    let (hub, _) = served().await;
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
    let (hub, rows) = served().await;
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
    rows.hold_at(CAT, "editor", "MENGER");
    assert_ne!(hub.view(Some(&who(CAT))).hash, before);
    assert_eq!(hub.view(Some(&who(CAT))).hash, view.hash, "now holding what ADA holds, CAT sees ADA's view");
}

#[tokio::test]
async fn hashes_follow_holdings() {
    let (hub, _) = served().await;
    let (a, b, c) = (hub.view(Some(&who(ADA))), hub.view(Some(&who(BOB))), hub.view(Some(&who(CAT))));
    assert_eq!(a.hash, b.hash);
    assert_ne!(a.hash, c.hash);
    assert_ne!(a.hash, hub.view(None).hash);
    assert!(hub.view(None).hash.starts_with("v-anon-"));
    assert!(a.hash.starts_with("v-") && !a.hash.starts_with("v-anon-"));
}

#[tokio::test]
async fn the_rpc_module_reads_the_connection() {
    let (hub, _) = served().await;
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
    let hub = Arc::new(DynamicHub::new("menger").register(TicketsActivation).register(MembersActivation));
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
    // (The answer's own keys: since SYNAPSE-CC-9 the `schema` method's
    // `returns` is SchemaResult's JSON Schema, which names both fields.)
    let text = t[0].to_string();
    assert!(t[0].get("view").is_none(), "{text}");
    assert!(t[0]["methods"].as_array().unwrap().iter().all(|m| m.get("held_on").is_none()), "{text}");
    assert_eq!(t[0]["methods"].as_array().unwrap().len(), 6);
    assert_eq!(hub.view(None).hash, hub.compute_hash());
    let h = data(hub.route("menger.hashes", json!({}), None).await.unwrap()).await;
    assert_eq!(h[0]["hash"], hub.compute_hash());
}

/// RETURNS-40: the service's `ir` is introspection — it runs for anyone,
/// anonymous included, as `<ns>.schema` does — and answers what the
/// caller's view shows, no more: built from the very schemas the caller is
/// answered, so it is equal to what synapse builds from them. Kept per view.
#[tokio::test]
async fn ir_is_introspection_and_answers_the_callers_view() {
    let (hub, _) = served().await;
    let ir_of = |auth: Option<AuthContext>| {
        let hub = hub.clone();
        async move {
            let got = data(hub.route("menger.ir", json!({}), auth.as_ref()).await.expect("ir runs")).await;
            assert_eq!(got.len(), 1, "{got:?}");
            got[0]["ok"].clone()
        }
    };
    let methods = |ir: &Value| -> Vec<String> {
        ir["irMethods"].as_object().unwrap().keys().filter(|k| !k.starts_with('.') && !k.ends_with(".schema")).cloned().collect()
    };

    // anonymous: the door alone, as the anonymous view shows it
    let anon = ir_of(None).await;
    assert!(anon.is_object(), "an anonymous caller is answered: {anon}");
    assert_eq!(methods(&anon), ["tickets.door"]);
    // a viewer: what the viewer's view shows
    let cat = ir_of(Some(who(CAT))).await;
    assert_eq!(methods(&cat), ["tickets.door", "tickets.get", "tickets.list"]);
    // admin: everything
    let root = ir_of(Some(who(ROOT))).await;
    assert_eq!(methods(&root), ["members.add", "tickets.delete", "tickets.door", "tickets.get", "tickets.list", "tickets.set_status"]);

    // equal to what synapse's walk builds from the schemas that caller is answered
    let mut schemas = BTreeMap::new();
    let ada = who(ADA);
    let root_schema = data(hub.route("menger.schema", Value::Null, Some(&ada)).await.unwrap()).await.remove(0);
    for child in root_schema["children"].as_array().unwrap() {
        let ns = child["namespace"].as_str().unwrap().to_string();
        let s = data(hub.route(&format!("{ns}.schema"), Value::Null, Some(&ada)).await.unwrap()).await.remove(0);
        schemas.insert(vec![ns], s);
    }
    schemas.insert(vec![], root_schema);
    let walked = plexus_core::plexus::ir::build("menger", &[vec![]], &schemas).unwrap().to_json();
    assert_eq!(ir_of(Some(ada)).await, walked);
}
