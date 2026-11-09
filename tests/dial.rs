//! VISION-5 (LOCAL-5) · services with no listening port reach each other
//! through a relay: each dials out (`Exposed`), offers its activation on its
//! own socket (spec/14) and is mounted at the relay as `peers.<name>`
//! (`Peers`) while the socket lives; the relay's gate decides every call.
//!
//! The relay here is plexus-transport's WebSocket server with `Peers` on
//! its connection hook, as `examples/relay.rs` runs it. Ports 4742–4759.

use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use futures::{Stream, StreamExt};
use plexus_auth_core::adapters::{Carriers, KeyProofAdapter};
use plexus_auth_core::identity::AuthenticatorChain;
use plexus_core::plexus::remote_child::{key_principal, DialOut, DialState, Exposed, PeerSocket, Peers};
use plexus_core::plexus::{AuthContext, Gate, MemoryMemberships, PlexusStreamItem, Resolve, RoleTable, ScopeRef};
use plexus_core::DynamicHub;
use plexus_transport::ws::{ConnectionHook, Hooks, Outbound};
use plexus_transport::TransportServer;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Greeting {
    pub text: String,
    pub caller: Option<String>,
}

#[derive(Clone)]
pub struct GreeterActivation {
    name: String,
}

#[plexus_macros::activation(crate_path = "plexus_core", version = "0.1.0", description = "a greeter behind no port")]
impl GreeterActivation {
    /// Greet, naming the caller the hop names.
    #[plexus_macros::method]
    async fn hello(&self, name: String) -> impl Stream<Item = Greeting> + Send + 'static {
        let from = self.name.clone();
        let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
        stream! { yield Greeting { text: format!("hello {name}, from {from}"), caller }; }
    }

    /// Count slowly: an open call to drop the peer under.
    #[plexus_macros::method]
    async fn count(&self, n: u32) -> impl Stream<Item = u32> + Send + 'static {
        stream! {
            for i in 0..n {
                yield i;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

struct Hook(Arc<PeerSocket>);
impl ConnectionHook for Hook {
    fn on_frame(&self, frame: &[u8]) -> bool {
        self.0.on_frame(frame)
    }
    fn on_close(&self) {
        self.0.on_close()
    }
}

fn port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(4742);
    loop {
        let p = NEXT.fetch_add(1, Ordering::SeqCst);
        assert!(p <= 4759, "no port left in 4742–4759");
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
}

/// A key file (0600) in `dir`, and its principal.
fn key(dir: &std::path::Path, name: &str, seed: u8) -> (std::path::PathBuf, String) {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("{name}.key"));
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([seed; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let p = key_principal(&path).unwrap();
    (path, p)
}

struct Relay {
    url: String,
    /// KEEL-8: the key the relay proves, which every peer names.
    principal: String,
    peers: Peers,
    service: Arc<DynamicHub>,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// A relay whose `member`s may offer and call every peer.
async fn relay(members: &[&str]) -> Relay {
    let port = port();
    let key = plexus_core::plexus::peer_token::PeerKey::generate();
    let principal = key.kid().to_string();
    let peers = Peers::new("peers", "relay", "service:relay").with_timeout(Duration::from_secs(5)).with_key(key);
    let plain = DynamicHub::new("relay").register(peers.clone());
    let base = RoleTable::from_lists(plain.declared_roles().iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let mut listed = MemoryMemberships::new();
    for m in members {
        listed = listed.with(m, "member", "*");
    }
    let gate = Arc::new(Gate::new(Arc::new(listed), Arc::new(peers.roles(base, Some("member"))), Arc::new(Everywhere)));
    peers.set_gate(Arc::clone(&gate));
    let service = Arc::new(plain.with_gate(gate));
    let weak = Arc::downgrade(&service);
    peers.on_change(move || {
        if let Some(s) = weak.upgrade() {
            s.schema_moved();
        }
    });
    let url = format!("ws://127.0.0.1:{port}/ws");
    let keys = KeyProofAdapter::new([url.clone()].iter()).unwrap();
    let chain = Carriers::cookie_and_bearer(AuthenticatorChain::new().with(Arc::new(keys)));
    let for_hook = peers.clone();
    let hooks = Hooks::new(move |conn, ext| {
        let auth = ext.get::<Arc<AuthContext>>().map(|a| (**a).clone());
        let writer = conn.writer()?;
        let (socket, mut out) = for_hook.socket(auth);
        tokio::spawn(async move {
            while let Some(f) = out.recv().await {
                if writer.send(Outbound::Text(String::from_utf8(f).unwrap())).await.is_err() {
                    break;
                }
            }
        });
        Some(Arc::new(Hook(socket)) as Arc<dyn ConnectionHook>)
    });
    let server = TransportServer::builder(Arc::clone(&service), |h| Ok(DynamicHub::arc_into_rpc_module(h)?))
        .without_registry()
        .with_websocket(port)
        .with_session_validator(Arc::new(chain))
        .anonymous_view()
        .reject_upgrade_on_auth_failure()
        .with_hooks(hooks)
        .with_allowed_hosts([format!("127.0.0.1:{port}")])
        .build()
        .await
        .unwrap();
    let serving = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Relay { url, principal, peers, service, serving }
}

/// A greeter that dials `relay` as `name`, signed in with `key`.
async fn peer(relay: &Relay, name: &str, key: &std::path::Path) -> Exposed {
    let exposed = Exposed::new(DialOut::new(relay.url.clone(), key).trust(relay.principal.clone()).mount(name).agent(name));
    exposed.serve(GreeterActivation { name: name.into() });
    exposed
}

async fn collect(s: plexus_core::plexus::PlexusStream) -> Vec<PlexusStreamItem> {
    s.collect().await
}

fn contents(items: &[PlexusStreamItem]) -> Vec<Value> {
    items
        .iter()
        .filter_map(|i| match i {
            PlexusStreamItem::Data { content, .. } => Some(content.clone().into_value()),
            _ => None,
        })
        .collect()
}

fn error_kind(items: &[PlexusStreamItem]) -> Option<String> {
    items.iter().find_map(|i| i.error_kind().map(str::to_string))
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never: {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_services_with_no_listening_port_reach_each_other_through_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, alice) = key(dir.path(), "alice", 1);
    let (kb, bob) = key(dir.path(), "bob", 2);
    let relay = relay(&[&alice, &bob]).await;
    let a = peer(&relay, "alice", &ka).await;
    let b = peer(&relay, "bob", &kb).await;
    assert_eq!(a.mounted(Duration::from_secs(10)).await.unwrap(), "peers.alice");
    assert_eq!(b.mounted(Duration::from_secs(10)).await.unwrap(), "peers.bob");

    // Who is connected is discovery: the relay's list, asked over a peer's own socket.
    let listed = contents(&collect(a.call("peers.list", json!({})).await).await);
    let names: Vec<&str> = listed.iter().filter_map(|p| p["name"].as_str()).collect();
    assert_eq!(names, ["alice", "bob"]);
    assert_eq!(listed[1]["principal"], bob.as_str());

    // alice calls bob, through the relay: bob's method runs, its caller alice.
    let items = collect(a.call("peers.bob.hello", json!({ "name": "carol" })).await).await;
    let said = contents(&items);
    assert_eq!(said, [json!({ "text": "hello carol, from bob", "caller": alice })], "{items:?}");
    // and back.
    let said = contents(&collect(b.call("peers.alice.hello", json!({ "name": "dan" })).await).await);
    assert_eq!(said[0]["text"], "hello dan, from alice");
    assert_eq!(said[0]["caller"], bob.as_str());

    // The relay's schema lists each peer as a child (what synapse navigates by).
    let schema = relay.peers.clone();
    let s = plexus_core::plexus::Activation::plugin_schema(&schema);
    #[allow(deprecated)]
    let kids: Vec<String> = s.children.unwrap_or_default().into_iter().map(|c| c.namespace).collect();
    assert_eq!(kids, ["alice", "bob"]);
    let _ = &relay.service;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_connection_removes_the_name_and_ends_its_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, alice) = key(dir.path(), "alice", 3);
    let (kb, bob) = key(dir.path(), "bob", 4);
    let relay = relay(&[&alice, &bob]).await;
    let a = peer(&relay, "alice", &ka).await;
    let b = peer(&relay, "bob", &kb).await;
    a.mounted(Duration::from_secs(10)).await.unwrap();
    b.mounted(Duration::from_secs(10)).await.unwrap();
    let mut events = relay.peers.events();

    // A call open into bob when bob's socket goes ends `child_unavailable`.
    let mut counting = a.call("peers.bob.count", json!({ "n": 1000 })).await;
    assert!(matches!(counting.next().await, Some(PlexusStreamItem::Data { .. })));
    b.stop();
    let rest: Vec<PlexusStreamItem> = tokio::time::timeout(Duration::from_secs(5), counting.collect()).await.expect("the call ends");
    assert_eq!(error_kind(&rest).as_deref(), Some("child_unavailable"), "{:?}", rest.last());

    // The name is gone: unlisted, said on the watch, and not reached.
    until("bob unmounted", || relay.peers.names() == ["alice"]).await;
    let mut said = None;
    while let Ok(Ok(e)) = tokio::time::timeout(Duration::from_secs(2), events.recv()).await {
        if let plexus_core::plexus::remote_child::PeerEvent::Unmounted { name, why } = e {
            said = Some((name, why));
            break;
        }
    }
    assert_eq!(said.map(|s| s.0).as_deref(), Some("bob"));
    let items = collect(a.call("peers.bob.hello", json!({ "name": "x" })).await).await;
    assert!(contents(&items).is_empty() && error_kind(&items).is_some(), "{items:?}");

    // bob dials again with the same key: mounted under the same name.
    let b = peer(&relay, "bob", &kb).await;
    b.mounted(Duration::from_secs(10)).await.unwrap();
    let said = contents(&collect(a.call("peers.bob.hello", json!({ "name": "again" })).await).await);
    assert_eq!(said[0]["text"], "hello again, from bob");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relays_gate_decides_who_may_offer_and_who_may_call() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, alice) = key(dir.path(), "alice", 5);
    let (km, mallory) = key(dir.path(), "mallory", 6);
    let (kb, _bob) = key(dir.path(), "bob", 7);
    let relay = relay(&[&alice]).await;
    let a = peer(&relay, "alice", &ka).await;
    a.mounted(Duration::from_secs(10)).await.unwrap();

    // Not a member: its offer is refused, typed; nothing is mounted.
    let m = peer(&relay, "mallory", &km).await;
    let refused = m.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("forbidden") && refused.contains("peers.offer"), "{refused}");
    assert!(matches!(m.state(), DialState::Refused { .. }));
    assert_eq!(relay.peers.names(), ["alice"]);

    // Another principal cannot take a name held: `name_taken`.
    let impostor = peer(&relay, "alice", &kb).await;
    let refused = impostor.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("forbidden") || refused.contains("name_taken"), "{refused}");

    // A caller the relay's gate does not admit never reaches the peer.
    let ctx = AuthContext::for_principal(&mallory.parse().unwrap(), "s", vec![], json!({}));
    let routed = relay.service.route("peers.alice.hello", json!({ "name": "x" }), Some(&ctx)).await;
    let refused = match routed {
        Err(e) => format!("{e:?}"),
        Ok(s) => format!("{:?}", collect(s).await),
    };
    assert!(refused.contains("Forbidden") || refused.contains("forbidden"), "{refused}");
    // A member does.
    let ctx = AuthContext::for_principal(&alice.parse().unwrap(), "s", vec![], json!({}));
    let items = collect(relay.service.route("peers.alice.hello", json!({ "name": "y" }), Some(&ctx)).await.unwrap()).await;
    assert_eq!(contents(&items)[0]["caller"], alice.as_str());
}
