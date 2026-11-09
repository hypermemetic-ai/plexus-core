//! NEST-15 — the service root is the primitive: a table of peers answered by
//! `peer(name)`, which can change while the service serves.
//!
//! The acceptance row: a service that starts with no activations grows a
//! top-level peer at runtime; a client reaches it (in process, through the
//! RPC module built before it came, and on a socket); its schema lists it
//! and the service's hash moves (watchers told); the gate admits it by role;
//! it goes again. Beside it: the builder is unchanged, a plain `Peer` is
//! served under a name of its own, and the root refuses what it must.

use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use plexus_core::plexus::{AuthContext, Peer, PeerError, PlexusStream, PlexusStreamItem, RootError};
use plexus_core::{DynamicHub, PlexusError};
use plexus_testkit::parts::who;
use plexus_testkit::{World, NOBODY, VIEWER};
use serde_json::{json, Value};

#[derive(Clone)]
struct WeatherActivation;

#[plexus_macros::activation(
    namespace = "weather",
    version = "1.0.0",
    description = "NEST-15 fixture: a peer grown at runtime",
    roles(viewer = ["forecast"]),
)]
impl WeatherActivation {
    /// Tomorrow's weather somewhere.
    #[plexus_macros::method]
    async fn forecast(&self, place: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("rain in {place}"); }
    }

    /// Not listed by any role: admin only.
    #[plexus_macros::method]
    async fn reset(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "reset".to_string(); }
    }
}

#[derive(Clone)]
struct EchoActivation;

#[plexus_macros::activation(namespace = "echo", version = "1.0.0", description = "NEST-15 fixture: a static entry")]
impl EchoActivation {
    /// Say it back.
    #[plexus_macros::method]
    async fn say(&self, text: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield text; }
    }
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

async fn errors(stream: PlexusStream) -> Vec<String> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Error { message, .. } => Some(message),
                _ => None,
            }
        })
        .collect()
        .await
}

/// The children `<service>.schema` lists, by namespace.
async fn children(hub: &DynamicHub, auth: Option<&AuthContext>) -> Vec<String> {
    let schema = data(hub.route(&format!("{}.schema", hub.runtime_namespace()), json!({}), auth).await.unwrap()).await;
    schema[0]["children"].as_array().map(|c| c.iter().map(|c| c["namespace"].as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

fn not_found(r: Result<PlexusStream, PlexusError>) -> bool {
    matches!(r, Err(PlexusError::ActivationNotFound(ns)) if ns == "weather")
}

#[tokio::test]
async fn a_service_with_no_activations_grows_a_top_level_peer() {
    let hub = DynamicHub::new("svc");
    let root = hub.root();
    assert!(root.names().is_empty());
    assert!(children(&hub, None).await.is_empty());
    let empty = root.hash();
    let mut watch = root.watch();
    assert!(not_found(hub.route("weather.forecast", json!({"place": "Oslo"}), None).await));

    // The table grows while the service serves.
    root.insert(WeatherActivation).unwrap();
    assert_eq!(root.names(), ["weather"]);
    // Watchers are told the new hash.
    tokio::time::timeout(Duration::from_secs(1), watch.changed()).await.unwrap().unwrap();
    let grown = watch.borrow_and_update().clone();
    assert_ne!(grown, empty);
    assert_eq!(grown, root.hash());

    // Reached by routing, as `peer(name)` from the root down…
    let out = data(hub.route("weather.forecast", json!({"place": "Oslo"}), None).await.unwrap()).await;
    assert_eq!(out, [json!("rain in Oslo")]);
    // …and as the primitive itself.
    let peer = root.peer("weather").await.unwrap();
    assert_eq!(peer.interface().name, "weather");
    let out = data(peer.call("forecast", json!({"place": "Bergen"}), None).await.unwrap()).await;
    assert_eq!(out, [json!("rain in Bergen")]);
    assert!(matches!(root.peer("nowhere").await, Err(PeerError::NotFound { name }) if name == "nowhere"));

    // Its schema lists it, and the service's own hash answer moved.
    assert_eq!(children(&hub, None).await, ["weather"]);
    let hash = data(hub.route("svc.hash", json!({}), None).await.unwrap()).await;
    assert_eq!(hash[0]["value"], json!(grown));
    let one = data(hub.route("weather.schema", json!({}), None).await.unwrap()).await;
    assert_eq!(one[0]["namespace"], "weather");
    let ir = hub.service_ir(&[], None).await.unwrap();
    assert!(ir.0.get().contains("forecast"), "the IR names the grown peer's methods");

    // A name taken is refused; replace takes it over.
    assert_eq!(root.insert(WeatherActivation), Err(RootError::Taken { name: "weather".into() }));
    assert_eq!(root.replace(WeatherActivation), Ok(true));

    // It goes again: not found, out of the schema, the hash back.
    assert!(root.remove("weather"));
    assert!(!root.remove("weather"));
    assert!(not_found(hub.route("weather.forecast", json!({"place": "Oslo"}), None).await));
    assert!(children(&hub, None).await.is_empty());
    assert_eq!(root.hash(), empty);
    tokio::time::timeout(Duration::from_secs(1), watch.changed()).await.unwrap().unwrap();
    assert_eq!(*watch.borrow(), empty);
}

#[tokio::test]
async fn the_builder_is_sugar_over_the_root() {
    // `register` at build and `insert` while serving give one table, one
    // schema, one hash.
    let built = DynamicHub::new("svc").register(EchoActivation).register(WeatherActivation);
    let grown = DynamicHub::new("svc");
    grown.root().insert(WeatherActivation).unwrap();
    grown.root().insert(EchoActivation).unwrap();
    assert_eq!(built.root().names(), grown.root().names());
    assert_eq!(built.compute_hash(), grown.compute_hash());
    assert_eq!(built.list_methods(), grown.list_methods());
    assert_eq!(children(&built, None).await, ["echo", "weather"]);
    // A registered entry is a peer like any other.
    let out = data(built.root().peer("echo").await.unwrap().call("say", json!({"text": "hi"}), None).await.unwrap()).await;
    assert_eq!(out, [json!("hi")]);
    // And may be removed while serving.
    assert!(built.root().remove("echo"));
    let gone = built.route("echo.say", json!({"text": "hi"}), None).await;
    assert!(matches!(gone, Err(PlexusError::ActivationNotFound(ns)) if ns == "echo"));
}

#[tokio::test]
async fn the_root_refuses_its_own_name_and_a_bad_one() {
    let hub = DynamicHub::new("weather");
    assert_eq!(hub.root().insert(WeatherActivation), Err(RootError::Shadows { name: "weather".into() }));
    let peer: Arc<dyn Peer> = Arc::new(EchoActivation);
    assert_eq!(hub.root().insert_peer("a.b", peer, false), Err(RootError::BadName { name: "a.b".into() }));
    assert!(hub.root().names().is_empty());
}

#[tokio::test]
async fn any_peer_is_served_under_a_name_of_its_own() {
    // A `Peer` (here an activation, erased) served as `sky`: its schema is
    // its interface's under `sky`, its grants requalified.
    let hub = DynamicHub::new("svc");
    let peer: Arc<dyn Peer> = Arc::new(WeatherActivation);
    assert_eq!(hub.root().insert_peer("sky", peer, false), Ok(false));
    let out = data(hub.route("sky.forecast", json!({"place": "Tromsø"}), None).await.unwrap()).await;
    assert_eq!(out, [json!("rain in Tromsø")]);
    assert_eq!(children(&hub, None).await, ["sky"]);
    let roles = hub.declared_roles();
    assert_eq!(roles["viewer"], ["sky.forecast"]);
    let schema = data(hub.route("sky.schema", json!({}), None).await.unwrap()).await;
    assert_eq!(schema[0]["namespace"], "sky");
}

#[tokio::test]
async fn a_client_reaches_it_through_the_module_built_before_it_came() {
    let hub = Arc::new(DynamicHub::new("svc"));
    let module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    hub.root().insert(WeatherActivation).unwrap();
    let mut p = jsonrpsee::core::params::ObjectParams::new();
    p.insert("method", "weather.forecast").unwrap();
    p.insert("params", json!({"place": "Oslo"})).unwrap();
    let mut sub = module.subscribe_unbounded("svc.call", p).await.unwrap();
    let (item, _) = sub.next::<Value>().await.unwrap().unwrap();
    assert_eq!(item["content"], "rain in Oslo", "{item}");

    // And on a socket: the service is served, then it grows.
    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let served = Arc::new(DynamicHub::new("live"));
    let handle = server.start(DynamicHub::arc_into_rpc_module(served.clone()).unwrap());
    let client = jsonrpsee::ws_client::WsClientBuilder::default().build(format!("ws://{addr}")).await.unwrap();
    let call = |method: &str, params: Value| {
        let mut p = jsonrpsee::core::params::ObjectParams::new();
        p.insert("method", method).unwrap();
        p.insert("params", params).unwrap();
        p
    };
    async fn first(client: &jsonrpsee::ws_client::WsClient, p: jsonrpsee::core::params::ObjectParams) -> Value {
        let mut sub: Subscription<Value> = client.subscribe("live.call", p, "live.call_unsub").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), sub.next()).await.unwrap().unwrap().unwrap()
    }
    let before = first(&client, call("weather.forecast", json!({"place": "Oslo"}))).await;
    assert_eq!(before["type"], "error", "{before}");
    served.root().insert(WeatherActivation).unwrap();
    let after = first(&client, call("weather.forecast", json!({"place": "Oslo"}))).await;
    assert_eq!(after["content"], "rain in Oslo", "{after}");
    // Its schema, on the socket.
    let mut sub: Subscription<Value> = client.subscribe("live.schema", jsonrpsee::rpc_params![], "live.schema_unsub").await.unwrap();
    let schema = tokio::time::timeout(Duration::from_secs(5), sub.next()).await.unwrap().unwrap().unwrap();
    let kids: Vec<&str> = schema["content"]["children"].as_array().unwrap().iter().map(|c| c["namespace"].as_str().unwrap()).collect();
    assert_eq!(kids, ["weather"], "{schema}");
    handle.stop().unwrap();
}

// ── the gate admits it by role ──────────────────────────────────────────────

#[tokio::test]
async fn the_gate_admits_a_grown_peer_by_role() {
    // VIEWER holds viewer; NOBODY nothing. The role names the grant before
    // the peer exists: a grant is a path.
    let host = World::new().host().named("svc").role("viewer", ["weather.forecast"]).await;
    let hub = host.service().clone();
    let (viewer, nobody) = (who(VIEWER), who(NOBODY));

    // Before: nothing to admit, and nothing in the viewer's schema.
    let before = hub.route("weather.forecast", json!({"place": "Oslo"}), Some(&viewer)).await;
    assert!(before.is_err() || !errors(before.unwrap()).await.is_empty());
    assert!(children(&hub, Some(&viewer)).await.is_empty());

    hub.root().insert(WeatherActivation).unwrap();

    // The viewer is admitted on `weather.forecast`, by role…
    let out = data(hub.route("weather.forecast", json!({"place": "Oslo"}), Some(&viewer)).await.unwrap()).await;
    assert_eq!(out, [json!("rain in Oslo")]);
    // …its view lists the peer with the method its role holds…
    assert_eq!(children(&hub, Some(&viewer)).await, ["weather"]);
    let schema = data(hub.route("weather.schema", json!({}), Some(&viewer)).await.unwrap()).await;
    let methods: Vec<&str> = schema[0]["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert!(methods.contains(&"forecast") && !methods.contains(&"reset"), "{methods:?}");
    // …and refused what no role lists; a caller with no role is refused.
    for (caller, method) in [(&viewer, "weather.reset"), (&nobody, "weather.forecast")] {
        let refused = hub.route(method, json!({"place": "Oslo"}), Some(caller)).await;
        assert!(matches!(refused, Err(PlexusError::Forbidden { .. })), "{method}: {:?}", refused.map(|_| ()));
    }

    // Gone: the gate has nothing to admit there any more.
    hub.root().remove("weather");
    let gone = hub.route("weather.forecast", json!({"place": "Oslo"}), Some(&viewer)).await;
    assert!(matches!(gone, Err(PlexusError::ActivationNotFound(_))), "{:?}", gone.map(|_| ()));
    assert!(children(&hub, Some(&viewer)).await.is_empty());
}
