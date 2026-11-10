//! NEST-7 · the primitive: an activation returns an activation.
//!
//! A host with a typed graft point (`forge::ForgePeer`, a contract) and an
//! untyped one (`Peer`): each returns a local implementation, a peer (the
//! contract's client over a `PeerTransport`) and every `PeerError`, and a
//! caller sees each as its typed error item. Host code calls `repos()` on
//! the `Box<dyn ForgePeer>` the same way for both. A `RemoteChild` is a
//! `Box<dyn Peer>`. A typed slot refuses a peer of another shape by
//! interface hash, and the client checks its stamp: `shape_mismatch` naming
//! `repos` against a backend whose `repos` changed, `drift` once against
//! one that only grew.

mod child_support;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_client::BoxFuture;
use plexus_core::plexus::peer::{Contract, Interface, Peer, PeerError, PeerTransport};
use plexus_core::plexus::{Activation, ChildOptions, InProcessTransport, MethodRole, PlexusStreamItem, RemoteChild};
use plexus_core::DynamicHub;
use plexus_testkit::parts::{items, who};
use plexus_testkit::{World, VIEWER};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------------ the contract

pub mod forge {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    pub struct Repo {
        pub name: String,
    }

    /// Why a forge said no — or could not be reached (`From<PeerError>`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ForgeError {
        Denied { why: String },
        Peer { error: PeerError },
    }

    impl From<PeerError> for ForgeError {
        fn from(error: PeerError) -> Self {
            ForgeError::Peer { error }
        }
    }

    /// A forge: repositories.
    #[plexus_macros::activation]
    impl ForgeActivation {
        /// Every repository.
        #[plexus_macros::method]
        pub async fn repos(&self) -> Result<Vec<Repo>, ForgeError>;

        /// One repository.
        #[plexus_macros::method]
        pub async fn repo(&self, name: String) -> Result<Repo, ForgeError>;
    }
}

use forge::{Forge, ForgeClient, ForgeError, ForgePeer, Repo};

/// A local forge, written by hand.
#[derive(Clone)]
struct GitHub;

impl Forge for GitHub {
    fn repos(&self) -> BoxFuture<'static, Result<Vec<Repo>, ForgeError>> {
        Box::pin(async { Ok(vec![Repo { name: "plexus-core".into() }, Repo { name: "menger".into() }]) })
    }

    fn repo(&self, name: String) -> BoxFuture<'static, Result<Repo, ForgeError>> {
        Box::pin(async move {
            if name == "secret" {
                Err(ForgeError::Denied { why: "private".into() })
            } else {
                Ok(Repo { name })
            }
        })
    }
}

// ------------------------------------------------------------------ other backends

pub mod grown {
    use super::*;

/// A backend that only grew: `repos` and `repo` as the contract's, and one more.
#[derive(Clone)]
pub struct GrownActivation;

/// A forge, grown.
#[plexus_macros::activation(namespace = "forge")]
impl GrownActivation {
    /// Every repository.
    #[plexus_macros::method]
    pub async fn repos(&self) -> Result<Vec<Repo>, ForgeError> {
        Ok(vec![Repo { name: "grown".into() }])
    }

    /// One repository.
    #[plexus_macros::method]
    pub async fn repo(&self, name: String) -> Result<Repo, ForgeError> {
        Ok(Repo { name })
    }

    /// Stars, new.
    #[plexus_macros::method]
    pub async fn stars(&self) -> Result<u64, ForgeError> {
        Ok(7)
    }
}

}

pub mod rebuilt {
    use super::*;

/// A rebuilt backend whose `repos` changed: it answers names now.
#[derive(Clone)]
pub struct RebuiltActivation;

/// A forge, rebuilt.
#[plexus_macros::activation(namespace = "forge")]
impl RebuiltActivation {
    /// Every repository's name.
    #[plexus_macros::method]
    pub async fn repos(&self) -> Result<Vec<String>, ForgeError> {
        Ok(vec!["rebuilt".into()])
    }

    /// One repository.
    #[plexus_macros::method]
    pub async fn repo(&self, name: String) -> Result<Repo, ForgeError> {
        Ok(Repo { name })
    }
}

}

use grown::GrownActivation;
use rebuilt::RebuiltActivation;

/// An untyped peer: any activation.
#[derive(Clone)]
pub struct GreeterActivation;

/// Says hello.
#[plexus_macros::activation]
impl GreeterActivation {
    /// Hello.
    pub async fn hello(&self, name: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("hello, {name}"); }
    }
}

// ------------------------------------------------------------------ the host

type Make = Arc<dyn Fn() -> Box<dyn ForgePeer> + Send + Sync>;

#[derive(Clone)]
pub struct HostActivation {
    remote: Make,
    wrong: Make,
}

/// A host with a typed graft point.
#[plexus_macros::activation(namespace = "host")]
impl HostActivation {
    /// The integrations' names.
    pub async fn integrations(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { for n in ["github", "remote"] { yield n.to_string(); } }
    }

    /// Host code: every integration's repositories, called natively —
    /// the local one and the peer through the same path.
    pub async fn all_repos(&self) -> impl Stream<Item = String> + Send + 'static {
        let mut names = Vec::new();
        for n in ["github", "remote"] {
            let gh: Box<dyn ForgePeer> = self.integration(n).await.expect("grafted");
            for r in gh.repos().await.expect("repos") {
                names.push(format!("{n}:{}", r.name));
            }
        }
        stream! { for n in names { yield n; } }
    }

    /// A typed peer: whatever is returned is a Forge.
    #[plexus_macros::peer(list = "integrations")]
    async fn integration(&self, name: &str) -> Result<Box<dyn ForgePeer>, PeerError> {
        match name {
            "github" => Ok(Box::new(GitHub.server())),
            "remote" => Ok((self.remote)()),
            "wrong" => Ok((self.wrong)()),
            "ghost" => Err(PeerError::NotGrafted { at: "host.integration".into(), name: name.into(), interface: "forge".into() }),
            "down" => Err(PeerError::Unavailable { reason: "the connection has closed".into() }),
            "slow" => Err(PeerError::Timeout),
            "secret" => Err(PeerError::Forbidden { grant: "host.{integration}.repos".into() }),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

#[derive(Clone)]
pub struct GardenActivation;

/// A garden of dendrites: an untyped graft point.
#[plexus_macros::activation(namespace = "garden")]
impl GardenActivation {
    /// The dendrites' names.
    pub async fn dendrites(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "greeter".to_string(); }
    }

    /// Names matching a query.
    fn find(&self, query: &str) -> impl Stream<Item = String> + Send + '_ {
        let hit = "greeter".contains(query);
        stream! { if hit { yield "greeter".to_string(); } }
    }

    /// An untyped peer: any activation.
    #[plexus_macros::peer(list = "dendrites", search = "find")]
    async fn dendrite(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match name {
            "greeter" => Ok(Box::new(GreeterActivation)),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

async fn host() -> HostActivation {
    let remote = ForgeClient::peer(InProcessTransport::new(GitHub.server())).await.expect("the backend is the stamp's");
    // A peer of another shape: checked (not admitted), so its interface is the rebuilt backend's.
    let t = PeerTransport::new(InProcessTransport::new(RebuiltActivation));
    t.check("forge", ForgeClient::<()>::stamp()).await.unwrap();
    let wrong = ForgeClient::at(t, "forge");
    HostActivation {
        remote: Arc::new(move || Box::new(remote.clone()) as Box<dyn ForgePeer>),
        wrong: Arc::new(move || Box::new(wrong.clone()) as Box<dyn ForgePeer>),
    }
}

async fn service() -> DynamicHub {
    DynamicHub::new("svc").register(host().await).register(GardenActivation)
}

async fn call(hub: &DynamicHub, method: &str, params: Value) -> Vec<Value> {
    match hub.route(method, params, None).await {
        Ok(s) => items(Ok(s)).await,
        Err(e) => vec![json!({ "dispatch_error": e.to_string() })],
    }
}

// ------------------------------------------------------------------ acceptance

/// The slot's role: typed with the contract's interface, untyped without.
#[test]
fn a_peer_slot_is_its_role() {
    let host = HostActivation::slot_schema().unwrap();
    let m = host.methods.iter().find(|m| m.name == "integration").unwrap();
    match &m.role {
        MethodRole::Peer { list_method, interface: Some(i), .. } => {
            assert_eq!(list_method.as_deref(), Some("integrations"));
            assert_eq!(i.name, "forge");
            assert_eq!(i, &<dyn ForgePeer as Contract>::interface());
            assert!(i.methods.contains_key("repos") && i.methods.contains_key("repo"));
        }
        other => panic!("{other:?}"),
    }
    let garden = GardenActivation::slot_schema().unwrap();
    let m = garden.methods.iter().find(|m| m.name == "dendrite").unwrap();
    assert!(
        matches!(&m.role, MethodRole::Peer { interface: None, list_method: Some(l), search_method: Some(s) } if l == "dendrites" && s == "find"),
        "{:?}",
        m.role
    );
    // On the wire: a static child (the slot) marked a peer — a reader that
    // knows only static and dynamic children navigates `slot.<name>` — and back.
    let wire = serde_json::to_value(&m.role).unwrap();
    assert_eq!(wire["kind"], "static_child", "{wire}");
    assert_eq!(wire["peer"], true);
    assert_eq!(serde_json::from_value::<MethodRole>(wire).unwrap(), m.role);
    let typed = serde_json::to_value(&host.methods.iter().find(|m| m.name == "integration").unwrap().role).unwrap();
    assert_eq!(typed["interface"]["name"], "forge");
}

/// Acceptance 1: a local impl, a peer, and each `PeerError` as its typed
/// error item.
#[tokio::test]
async fn a_host_returns_a_local_impl_a_peer_and_each_peer_error() {
    let hub = service().await;
    // A one-item `Result` is `{"ok": …}` / `{"err": …}` on the wire.
    assert_eq!(
        call(&hub, "host.integration.github.repos", json!({})).await,
        vec![json!({ "ok": [{ "name": "plexus-core" }, { "name": "menger" }] })]
    );
    assert_eq!(
        call(&hub, "host.integration.remote.repos", json!({})).await,
        vec![json!({ "ok": [{ "name": "plexus-core" }, { "name": "menger" }] })]
    );
    assert_eq!(call(&hub, "host.integration.remote.repo", json!({ "name": "x" })).await, vec![json!({ "ok": { "name": "x" } })]);
    // A forge's own refusal is data, through either.
    for at in ["github", "remote"] {
        let got = call(&hub, &format!("host.integration.{at}.repo"), json!({ "name": "secret" })).await;
        assert_eq!(got, vec![json!({ "err": { "type": "denied", "why": "private" } })], "{at}");
    }
    // The untyped slot: any activation, admitted whole.
    assert_eq!(call(&hub, "garden.dendrite.greeter.hello", json!({ "name": "world" })).await, vec![json!("hello, world")]);

    let kinds = [
        ("host.integration.ghost.repos", "not_grafted", json!({ "at": "host.integration", "name": "ghost", "interface": "forge" })),
        ("host.integration.down.repos", "unavailable", json!({ "reason": "the connection has closed" })),
        ("host.integration.slow.repos", "timeout", json!({})),
        ("host.integration.secret.repos", "forbidden", json!({ "grant": "host.{integration}.repos" })),
        ("host.integration.nobody.repos", "not_found", json!({ "name": "nobody" })),
        ("garden.dendrite.nobody.hello", "not_found", json!({ "name": "nobody" })),
    ];
    for (method, kind, fields) in kinds {
        let got = call(&hub, method, json!({})).await;
        assert_eq!(got.len(), 1, "{method}: {got:?}");
        let item = &got[0];
        assert_eq!(item["type"], "error", "{method}: {item}");
        assert_eq!(item["error_kind"], kind, "{method}: {item}");
        for (k, v) in fields.as_object().unwrap() {
            assert_eq!(&item[k], v, "{method}: `{k}` in {item}");
        }
        // Never "method not found".
        assert_ne!(item["code"], "-32601", "{method}: {item}");
        // And a client reads it back typed.
        let back: PlexusStreamItem = serde_json::from_value(item.clone()).unwrap();
        let pe = PeerError::from_item(&back).expect("a typed peer error");
        assert_eq!(pe.kind(), kind);
    }
}

/// Acceptance 2: host code calls `repos()` on the `Box<dyn ForgePeer>` for
/// the local impl and the peer through the same code path.
#[tokio::test]
async fn host_code_calls_the_local_and_the_peer_the_same_way() {
    let hub = service().await;
    assert_eq!(
        call(&hub, "host.all_repos", json!({})).await,
        vec![json!("github:plexus-core"), json!("github:menger"), json!("remote:plexus-core"), json!("remote:menger")]
    );
    // And each is a `Peer` (upcast) with the contract's shape.
    let host = host().await;
    for n in ["github", "remote"] {
        let p: Box<dyn Peer> = host.integration(n).await.unwrap();
        assert!(p.interface().satisfies(&<dyn ForgePeer as Contract>::interface()).is_ok(), "{n}");
    }
}

/// Acceptance 4: a typed slot refuses a peer of another shape with
/// `ShapeMismatch`, by interface hash.
#[tokio::test]
async fn a_typed_slot_refuses_another_shape_by_interface_hash() {
    let hub = service().await;
    let got = call(&hub, "host.integration.wrong.repo", json!({ "name": "x" })).await;
    let item = &got[0];
    assert_eq!(item["error_kind"], "shape_mismatch", "{item}");
    assert_eq!(item["wanted"], json!(<dyn ForgePeer as Contract>::interface().hash));
    let rebuilt = Interface::named("forge", &RebuiltActivation.plugin_schema());
    assert_eq!(item["got"], json!(rebuilt.hash));
    assert_eq!(item["methods"], json!(["repos"]));
}

/// Acceptance 3: a `RemoteChild` is held as a `Box<dyn Peer>` and called
/// through it, unchanged.
#[tokio::test]
async fn a_remote_child_is_a_peer() {
    let dir = tempfile::tempdir().unwrap();
    let spec = child_support::stdio_spec("echo", &dir.path().join("l"), "");
    let child = RemoteChild::connect(spec, ChildOptions::default()).await.expect("the stub mounts");
    let direct = items(Ok(Activation::call(&child, "echo", json!({ "text": "hi" }), None, None).await.unwrap())).await;
    let peer: Box<dyn Peer> = Box::new(child);
    let through = items(Ok(peer.call("echo", json!({ "text": "hi" }), None).await.unwrap())).await;
    assert_eq!(through, direct);
    assert!(!through.is_empty());
    assert_eq!(peer.interface().name, "echo");
    assert!(peer.interface().methods.contains_key("echo"), "{:?}", peer.interface().methods);
}

/// A transport that says the backend it reaches is `plexus_hash`, switchable
/// between two backends — a backend rebuilt under a running client.
#[derive(Clone)]
struct Switch {
    now: Arc<Mutex<usize>>,
    v1: InProcessTransport<forge::ForgeActivation<GitHub>>,
    v2: InProcessTransport<RebuiltActivation>,
}

impl plexus_client::Transport for Switch {
    fn call(&self, method: plexus_client::MethodRef, params: Value) -> plexus_client::ItemStream<'_> {
        use plexus_client::Transport;
        let which = *self.now.lock().unwrap();
        let hash = if which == 0 { "h-v1" } else { "h-v2" }.to_string();
        let items = if which == 0 { self.v1.call(method, params) } else { self.v2.call(method, params) };
        Box::pin(items.map(move |item| {
            item.map(|mut i| {
                match &mut i {
                    plexus_client::StreamItem::Data { metadata: Some(m), .. }
                    | plexus_client::StreamItem::Error { metadata: Some(m), .. }
                    | plexus_client::StreamItem::Done { metadata: Some(m) } => m.plexus_hash = hash.clone(),
                    _ => {}
                }
                i
            })
        }))
    }
}

/// Acceptance 5 (the Rust client): against a rebuilt backend whose `repos`
/// changed, `shape_mismatch` naming `repos`; against one that only grew,
/// `drift` once, and it works; a backend rebuilt under a running client is
/// caught by its items' `plexus_hash`.
#[tokio::test]
async fn the_client_checks_its_stamp() {
    let stamp = ForgeClient::<()>::stamp();
    assert_eq!(stamp.interface, "forge");
    assert_eq!(stamp.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(stamp.hash, <dyn ForgePeer as Contract>::interface().hash);
    let names: Vec<&str> = stamp.methods.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["repo", "repos"]);

    // The backend it was generated from: equal hashes.
    let same = ForgeClient::peer(InProcessTransport::new(GitHub.server())).await.unwrap();
    assert!(same.transport().drift().is_none());

    // Rebuilt, `repos` changed: refused as a peer, naming `repos`.
    let e = ForgeClient::peer(InProcessTransport::new(RebuiltActivation)).await.err().expect("refused");
    match &e {
        PeerError::ShapeMismatch { wanted, methods, .. } => {
            assert_eq!(wanted, &stamp.hash);
            assert_eq!(methods, &["repos".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(serde_json::to_value(&e).unwrap()["error_kind"], "shape_mismatch");

    // Grown: drift once, and it works — `repos` and `repo` through the trait.
    let grown = ForgeClient::peer(InProcessTransport::new(GrownActivation)).await.unwrap();
    let drift = grown.transport().drift().expect("drift");
    assert_eq!(drift.from, stamp.hash);
    let as_forge: Box<dyn ForgePeer> = Box::new(grown.clone());
    assert_eq!(as_forge.repos().await.unwrap(), vec![Repo { name: "grown".into() }]);
    assert_eq!(as_forge.repo("y".into()).await.unwrap(), Repo { name: "y".into() });
    assert_eq!(grown.transport().drifts_said(), 1, "drift is said once");

    // Rebuilt under a running client: the items' plexus_hash moves, the
    // client asks again once, and the method that moved fails while the
    // other goes on.
    let now = Arc::new(Mutex::new(0));
    let switch = Switch { now: now.clone(), v1: InProcessTransport::new(GitHub.server()), v2: InProcessTransport::new(RebuiltActivation) };
    let client = ForgeClient::peer(switch).await.unwrap();
    let f: Box<dyn ForgePeer> = Box::new(client.clone());
    assert_eq!(f.repos().await.unwrap().len(), 2);
    let checks = client.transport().checks();
    *now.lock().unwrap() = 1;
    // This call's items say h-v2: asked again, and `repo` did not move.
    assert_eq!(f.repo("z".into()).await.unwrap(), Repo { name: "z".into() });
    assert_eq!(client.transport().checks(), checks + 1, "asked again once");
    match f.repos().await {
        Err(ForgeError::Peer { error: PeerError::ShapeMismatch { methods, .. } }) => assert_eq!(methods, ["repos"]),
        other => panic!("{other:?}"),
    }
    assert_eq!(client.transport().checks(), checks + 1, "not asked again while the hash stands");
}

// ------------------------------------------------------------------ the slot grant

/// NEST-5's slot grant on a peer slot: `host.{integration}.repos` is
/// `repos` on every peer in the slot; an untyped slot is granted whole,
/// `garden.{dendrite}`; `auth.requires` answers them.
#[tokio::test]
async fn a_peer_slot_is_granted_once() {
    // VIEWER holds viewer, which lists the two slot grants and nothing else.
    let served = World::new()
        .host()
        .named("svc")
        .with(host().await)
        .with(GardenActivation)
        .role("viewer", ["host.{integration}.repos", "garden.{dendrite}"])
        .with_auth()
        .await;
    let hub = served.service().clone();
    let viewer = who(VIEWER);
    let as_viewer = |m: &'static str, p: Value| {
        let hub = &hub;
        let viewer = viewer.clone();
        async move {
            match hub.route(m, p, Some(&viewer)).await {
                Ok(s) => format!("ok:{}", items(Ok(s)).await.first().cloned().unwrap_or_default()),
                Err(e) => format!("refused:{e}"),
            }
        }
    };
    assert!(as_viewer("host.integration.github.repos", json!({})).await.starts_with("ok:{\"ok\""));
    assert!(as_viewer("host.integration.remote.repos", json!({})).await.starts_with("ok:{\"ok\""));
    let r = as_viewer("host.integration.github.repo", json!({ "name": "x" })).await;
    assert!(r.starts_with("refused:") && r.contains("host.{integration}.repo"), "{r}");
    assert!(as_viewer("garden.dendrite.greeter.hello", json!({ "name": "w" })).await.starts_with("ok:\"hello, w\""));
    // auth.requires: the slot's grant.
    let req = |m: &'static str| {
        let hub = &hub;
        let viewer = viewer.clone();
        async move { items(Ok(hub.route("auth.requires", json!({ "method": m }), Some(&viewer)).await.unwrap())).await[0]["grant"].clone() }
    };
    assert_eq!(req("host.integration.github.repos").await, "host.{integration}.repos");
    assert_eq!(req("garden.dendrite.greeter.hello").await, "garden.{dendrite}");
}
