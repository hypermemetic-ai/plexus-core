//! PERF-7's hazard, held (PERF-17's finding, PLEXUS/PERF-18): with each
//! item encoded once from its typed event, an encoded item slipped past the
//! gated view's rewrite and an anonymous caller saw the ungated schema.
//!
//! The rule this file holds: **what a caller reads over the wire is what the
//! service answers that caller in process** — every self-description
//! (`_info`, `<ns>.schema`, `<ns>.hash`, a child's schema, a method's) and
//! every item, anonymous and signed in, through plexus-transport's WebSocket
//! (the socket loop's own frames) and through the RPC module (jsonrpsee's
//! sink). In process, `route()` answers from the caller's view with every
//! transformer applied to a `Value`; on the wire the same answer leaves as
//! bytes encoded once. A transformer that rewrites `Data` and misses an
//! encoded item makes the two differ — the anonymous `menger.schema` naming
//! `tickets`, the site hints missing — and this file goes red.

use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use plexus_auth_core::{AuthMechanism, BackendAuthCapabilities, HeaderName};
use plexus_core::plexus::{
    AuthContext, AuthSetup, MemoryAuthBackend, MemoryMemberships, MemoryRoles, PlexusStream, PlexusStreamItem, Reach, Resolve, ScopeRef,
    SessionValidator,
};
use plexus_core::DynamicHub;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// The service: AUTH-4's tickets activation behind the gate
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TicketsActivation;

/// A row with its fields in no sorted order, so an item encoded from its
/// type and one written from a `Value` differ in their bytes and agree as
/// JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TicketEvent {
    Ticket { title: String, id: String, status: String, blocked_by: Vec<String>, body: Option<String> },
    Held { scopes: String },
    Said { line: String },
}

impl plexus_client::FromClientError for TicketEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        TicketEvent::Said { line: error.to_string() }
    }
}

#[plexus_macros::activation(
    version = "0.5.0",
    description = "Plans as data",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl TicketsActivation {
    /// One ticket by id.
    #[plexus_macros::method(target = "id", description = "One ticket by id")]
    async fn get(&self, id: String) -> impl Stream<Item = TicketEvent> + Send + 'static {
        stream! {
            yield TicketEvent::Ticket { title: format!("the {id} \"quoted\" ünïcode"), id: id.clone(), status: "Ready".into(), blocked_by: vec!["MENGER-2".into()], body: None };
        }
    }

    /// Tickets, from where the caller holds them.
    #[plexus_macros::method(description = "Tickets, filtered and paged")]
    async fn list(&self, reach: Reach) -> impl Stream<Item = TicketEvent> + Send + 'static {
        let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        stream! {
            for n in 0..3 {
                yield TicketEvent::Ticket { title: format!("row {n}"), id: format!("MENGER-{n}"), status: "Pending".into(), blocked_by: vec![], body: Some("b".repeat(n)) };
            }
            yield TicketEvent::Held { scopes: held.join(",") };
        }
    }

    /// Change a ticket's status.
    #[plexus_macros::method(target = "id", description = "Change a ticket's status")]
    async fn set_status(&self, auth: &AuthContext, id: String, status: String) -> impl Stream<Item = TicketEvent> + Send + 'static {
        let _ = auth;
        stream! { yield TicketEvent::Said { line: format!("{id} -> {status}") }; }
    }

    /// Listed by no role: admin only.
    #[plexus_macros::method(target = "id", description = "Delete a ticket")]
    async fn delete(&self, id: String) -> impl Stream<Item = TicketEvent> + Send + 'static {
        stream! { yield TicketEvent::Said { line: id }; }
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
const ROOT: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn key(p: &str, agent: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "kp-1", vec![], json!({"agent": agent, "name": agent}))
}

/// AUTH-4's gated service: ada an editor on MENGER, root admin everywhere.
/// With `scopes`, R-5's scope gate is configured too (an empty registry):
/// its introspection is routed on every call and its content replaced as
/// the stream is read — the rewrite a lazily encoded item meets on the wire.
fn gated(scopes: bool) -> Arc<DynamicHub> {
    let backend = Arc::new(MemoryAuthBackend::new("http://127.0.0.1:4456/login"));
    let roles = Arc::new(MemoryRoles::default());
    let memberships = Arc::new(MemoryMemberships::new().with(ADA, "editor", "MENGER").with(ROOT, "admin", "*"));
    let mut hub = DynamicHub::new("menger").register(TicketsActivation);
    if scopes {
        hub = hub.with_scope_registry(plexus_auth_core::ScopeRegistry::builder().build().unwrap());
    }
    let hub = hub
        .with_auth(AuthSetup::new(backend, roles.clone(), memberships, Arc::new(Shortcodes)))
        .with_resource_metadata("http://127.0.0.1:4456/.well-known/oauth-protected-resource");
    roles.seed(&hub.declared_roles());
    Arc::new(hub)
}

/// CA-1's service: no gate, a bearer header advertised, so every schema
/// leaving it has its `site_hint` filled by `fill_site_hints_in_schema_stream`.
fn site_hinted() -> Arc<DynamicHub> {
    let caps = BackendAuthCapabilities::new(vec![AuthMechanism::Bearer { header: HeaderName::try_new("authorization").unwrap() }], Some(0)).unwrap();
    Arc::new(DynamicHub::new("vaults").register(VaultActivation).with_auth_capabilities(caps))
}

#[derive(Clone)]
struct VaultActivation;

#[plexus_macros::activation(version = "1.0.0", description = "CA-1 site-hint fixture")]
impl VaultActivation {
    /// Scope-gated: carries a `requires_credential` whose site the hub fills.
    #[plexus_macros::method(scope = "vault.write")]
    async fn write(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "wrote".to_string(); }
    }
}

// ---------------------------------------------------------------------------
// Reading an answer three ways
// ---------------------------------------------------------------------------

/// A stream's answer as a client reads it: each `data` item's content, each
/// `error` item as `{error: message}`, in order.
async fn in_process(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(serde_json::to_value(&content).unwrap()),
                PlexusStreamItem::Error { message, .. } => Some(json!({"error": message})),
                _ => None,
            }
        })
        .collect()
        .await
}

/// What `who` gets from `route(method, params)`: its items, or the refusal.
async fn routed(hub: &DynamicHub, method: &str, params: &Value, who: Option<&AuthContext>) -> Vec<Value> {
    match hub.route(method, params.clone(), who).await {
        Ok(s) => in_process(s).await,
        Err(e) => vec![json!({"refused": e.to_string()})],
    }
}

/// A wire item (`params.result`) as [`in_process`] reads one.
fn read(item: &Value) -> Option<Value> {
    match item["type"].as_str() {
        Some("data") => Some(item["content"].clone()),
        Some("error") => Some(json!({"error": item["message"]})),
        _ => None,
    }
}

/// `who`'s socket on a plexus-transport WebSocket: a bearer token names it.
struct Tokens;
#[async_trait::async_trait]
impl SessionValidator for Tokens {
    async fn validate(&self, token: &str) -> Option<AuthContext> {
        match token {
            "ada" => Some(key(ADA, "worker-1")),
            "root" => Some(key(ROOT, "root")),
            _ => None,
        }
    }
}

async fn serve(hub: Arc<DynamicHub>) -> (plexus_transport::ServerHandle, String) {
    let module = DynamicHub::arc_into_rpc_module(hub).unwrap();
    let opts = plexus_transport::websocket::UpgradeOptions { anonymous_view: true, ..Default::default() };
    let (handle, addr) = plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(0), Some(Arc::new(Tokens)), opts)
        .await
        .unwrap();
    (handle, format!("ws://{addr}"))
}

async fn socket(url: &str, token: Option<&str>) -> WsClient {
    let mut headers = http::HeaderMap::new();
    if let Some(t) = token {
        headers.insert("authorization", format!("Bearer {t}").parse().unwrap());
    }
    WsClientBuilder::default().set_headers(headers).build(url).await.unwrap()
}

/// Over the socket: `method` subscribed (`<ns>.call`, `_info`, …), its items
/// until `done`.
async fn over_socket(ws: &WsClient, method: &str, params: ObjectParams) -> Vec<Value> {
    let unsub = format!("{method}_unsub");
    let mut sub: Subscription<Value> = match ws.subscribe(method, params, &unsub).await {
        Ok(s) => s,
        Err(e) => return vec![json!({"refused": e.to_string()})],
    };
    let mut out = Vec::new();
    loop {
        // A refused call is one error item and no `done` (`<ns>.call`'s
        // refusal): after an error, a quiet moment ends the answer.
        let wait = if out.last().is_some_and(|v: &Value| v.get("error").is_some()) { Duration::from_millis(300) } else { Duration::from_secs(5) };
        let item = match tokio::time::timeout(wait, sub.next()).await {
            Ok(i) => i.expect("the stream is open").unwrap(),
            Err(_) if wait < Duration::from_secs(1) => return out,
            Err(_) => panic!("{method}: no item in 5 s after {out:?}"),
        };
        if item["type"] == "done" {
            return out;
        }
        out.extend(read(&item));
    }
}

fn call_params(method: &str, params: &Value) -> ObjectParams {
    let mut p = ObjectParams::new();
    p.insert("method", method).unwrap();
    p.insert("params", params.clone()).unwrap();
    p
}

/// Through the RPC module (jsonrpsee's own sink: the path a transport
/// without the socket loop's frames takes).
async fn over_module(module: &jsonrpsee::RpcModule<()>, method: &str, params: Value) -> Vec<Value> {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let (_resp, mut rx) = module.raw_json_request(&req.to_string(), 64).await.unwrap();
    let mut out = Vec::new();
    while let Ok(Some(m)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        let v: Value = serde_json::from_str(m.get()).unwrap();
        let item = &v["params"]["result"];
        if item["type"] == "done" {
            break;
        }
        out.extend(read(item));
    }
    out
}

/// Every call a caller can make of the gated service, through `menger.call`.
fn calls() -> Vec<(&'static str, Value)> {
    vec![
        ("menger.schema", json!({})),
        ("menger.hash", json!({})),
        ("menger.hashes", json!({})),
        ("auth.schema", json!({})),
        ("auth.schema", json!({"method": "login"})),
        ("auth.login.schema", json!({})),
        ("tickets.schema", json!({})),
        ("tickets.schema", json!({"method": "get"})),
        ("tickets.get.schema", json!({})),
        ("auth.providers", json!({})),
        ("auth.whoami", json!({})),
        ("tickets.get", json!({"id": "MENGER-1"})),
        ("tickets.list", json!({})),
        ("tickets.set_status", json!({"id": "MENGER-1", "status": "Ready"})),
    ]
}

/// The callers: nobody, ada (an editor on MENGER) and root (admin on `*`).
fn callers() -> Vec<(&'static str, Option<AuthContext>)> {
    vec![("anonymous", None), ("ada", Some(key(ADA, "worker-1"))), ("root", Some(key(ROOT, "root")))]
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

/// A refusal reads differently on each path (an `Err` in process, an error
/// item or a JSON-RPC error on the wire); what must agree is that it is one.
fn refused(items: &[Value]) -> bool {
    items.len() == 1 && (items[0].get("refused").is_some() || items[0].get("error").is_some())
}

fn agree(what: &str, wire: &[Value], here: &[Value]) {
    if refused(here) {
        assert!(refused(wire), "{what}: refused in process, answered on the wire: {wire:?}");
        return;
    }
    assert_eq!(wire, here, "{what}: the wire is not what the service answers this caller");
}

#[tokio::test]
async fn behind_the_gate_every_caller_reads_on_the_wire_what_it_is_answered_in_process() {
    every_caller_reads_what_it_is_answered(gated(false)).await;
}

#[tokio::test]
async fn behind_the_scope_gate_too_every_caller_reads_on_the_wire_what_it_is_answered_in_process() {
    every_caller_reads_what_it_is_answered(gated(true)).await;
}

async fn every_caller_reads_what_it_is_answered(hub: Arc<DynamicHub>) {
    let (_server, url) = serve(hub.clone()).await;
    let mut seen_views = Vec::new();
    for (name, who) in callers() {
        let ws = socket(&url, match name {
            "anonymous" => None,
            other => Some(other),
        })
        .await;
        let mut module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
        if let Some(w) = &who {
            module.extensions_mut().insert(Arc::new(w.clone()));
        }

        // The service's own self-description, asked directly.
        let info = over_socket(&ws, "_info", ObjectParams::new()).await;
        assert_eq!(info, vec![hub.info(who.as_ref())], "{name}: _info on the wire");
        assert_eq!(over_module(&module, "_info", json!({})).await, vec![hub.info(who.as_ref())], "{name}: _info through the module");
        let view = hub.view(who.as_ref());
        let hash = over_socket(&ws, "menger.hash", ObjectParams::new()).await;
        assert_eq!(hash, routed(&hub, "menger.hash", &json!({}), who.as_ref()).await, "{name}: menger.hash on the wire");
        assert_eq!(hash[0]["value"], view.hash, "{name}: the hash is the caller's view's");
        seen_views.push(view.hash.clone());

        // Every call, through `<ns>.call`: the wire against the service.
        for (method, params) in calls() {
            let here = routed(&hub, method, &params, who.as_ref()).await;
            let wire = over_socket(&ws, "menger.call", call_params(method, &params)).await;
            agree(&format!("{name} {method} {params} (socket)"), &wire, &here);
            let wire = over_module(&module, "menger.call", json!({"method": method, "params": params})).await;
            agree(&format!("{name} {method} {params} (module)"), &wire, &here);
        }

        // Not vacuous: the views differ, and each schema is the caller's.
        let schema = routed(&hub, "menger.schema", &json!({}), who.as_ref()).await;
        let kids: Vec<&str> = schema[0]["children"].as_array().unwrap().iter().map(|c| c["namespace"].as_str().unwrap()).collect();
        match name {
            "anonymous" => {
                assert_eq!(schema[0]["view"], "anonymous");
                assert_eq!(kids, vec!["auth"], "the anonymous view names auth alone");
            }
            _ => assert!(kids.contains(&"tickets"), "{name} sees tickets: {kids:?}"),
        }
    }
    seen_views.dedup();
    assert_eq!(seen_views.len(), 3, "three callers, three views");
}

#[tokio::test]
async fn a_schema_leaving_a_service_carries_its_site_hints_on_the_wire() {
    let hub = site_hinted();
    let (_server, url) = serve(hub.clone()).await;
    let ws = socket(&url, None).await;
    let module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    for (method, params) in [("vault.schema", json!({})), ("vault.schema", json!({"method": "write"})), ("vault.write.schema", json!({}))] {
        let here = routed(&hub, method, &params, None).await;
        let text = serde_json::to_string(&here).unwrap();
        assert!(text.contains("site_hint"), "{method}: the hub fills the site hint in process: {text}");
        agree(&format!("{method} {params} (socket)"), &over_socket(&ws, "vaults.call", call_params(method, &params)).await, &here);
        agree(&format!("{method} {params} (module)"), &over_module(&module, "vaults.call", json!({"method": method, "params": params})).await, &here);
    }
}
